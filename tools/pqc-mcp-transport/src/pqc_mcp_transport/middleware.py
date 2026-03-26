"""ASGI middleware that adds PQC verification to MCP HTTP servers."""

from __future__ import annotations

import json
from typing import Any, Callable, Awaitable

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.errors import SignatureVerificationError
from pqc_mcp_transport.signer import MessageSigner


class PQCMiddleware:
    """ASGI middleware that intercepts MCP JSON-RPC requests to verify PQC
    signatures and signs outgoing responses.

    Usage with Starlette / FastAPI::

        from starlette.applications import Starlette
        from pqc_mcp_transport.middleware import PQCMiddleware

        app = Starlette(...)
        app = PQCMiddleware(app, server_identity=my_identity)
    """

    def __init__(
        self,
        app: Any,
        server_identity: AgentIdentity,
        require_auth: bool = True,
    ) -> None:
        self.app = app
        self.identity = server_identity
        self.signer = MessageSigner(server_identity)
        self._require_auth = require_auth

    async def __call__(
        self,
        scope: dict,
        receive: Callable[..., Awaitable[dict]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Accumulate request body
        body_parts: list[bytes] = []
        request_complete = False

        async def receive_wrapper() -> dict:
            nonlocal request_complete
            message = await receive()
            if message["type"] == "http.request":
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    request_complete = True
            return message

        # Buffer the response body so we can sign it
        response_started = False
        response_status = 200
        response_headers: list[tuple[bytes, bytes]] = []
        response_body_parts: list[bytes] = []

        async def send_wrapper(message: dict) -> None:
            nonlocal response_started, response_status, response_headers

            if message["type"] == "http.response.start":
                response_started = True
                response_status = message.get("status", 200)
                response_headers = list(message.get("headers", []))
                return  # Don't send yet; wait for body

            if message["type"] == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                response_body_parts.append(body)

                if not more_body:
                    # All body received: attempt to sign JSON responses
                    full_body = b"".join(response_body_parts)
                    content_type = ""
                    for k, v in response_headers:
                        if k.lower() == b"content-type":
                            content_type = v.decode("utf-8", errors="replace")
                            break

                    if "json" in content_type:
                        try:
                            data = json.loads(full_body)
                            signed = self.signer.sign_message(data)
                            full_body = json.dumps(signed).encode("utf-8")
                        except (json.JSONDecodeError, Exception):
                            pass  # If not valid JSON, pass through

                    # Update Content-Length
                    new_headers = [
                        (k, v)
                        for k, v in response_headers
                        if k.lower() != b"content-length"
                    ]
                    new_headers.append(
                        (b"content-length", str(len(full_body)).encode("utf-8"))
                    )

                    await send(
                        {
                            "type": "http.response.start",
                            "status": response_status,
                            "headers": new_headers,
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": full_body,
                        }
                    )
                return

            # Pass through other message types
            await send(message)

        # Verify incoming request (read body, check signature, then replay to app)
        if self._require_auth and scope.get("method", "").upper() == "POST":
            # We need to read the body first to verify, then re-feed it to the app
            body_chunks: list[bytes] = []
            while True:
                msg = await receive()
                if msg["type"] == "http.request":
                    body_chunks.append(msg.get("body", b""))
                    if not msg.get("more_body", False):
                        break

            full_request_body = b"".join(body_chunks)

            # Try to verify PQC signature
            try:
                request_data = json.loads(full_request_body)
                if "_pqc" in request_data:
                    vr = MessageSigner.verify_message(request_data)
                    if not vr.valid:
                        # Return 403
                        error_body = json.dumps(
                            {"error": f"PQC signature verification failed: {vr.error}"}
                        ).encode("utf-8")
                        await send(
                            {
                                "type": "http.response.start",
                                "status": 403,
                                "headers": [
                                    (b"content-type", b"application/json"),
                                    (
                                        b"content-length",
                                        str(len(error_body)).encode("utf-8"),
                                    ),
                                ],
                            }
                        )
                        await send(
                            {"type": "http.response.body", "body": error_body}
                        )
                        return
            except (json.JSONDecodeError, Exception):
                pass  # Not JSON — pass through to app

            # Replay body to inner app
            body_sent = False

            async def replay_receive() -> dict:
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {
                        "type": "http.request",
                        "body": full_request_body,
                        "more_body": False,
                    }
                return await receive()

            await self.app(scope, replay_receive, send_wrapper)
        else:
            await self.app(scope, receive, send_wrapper)
