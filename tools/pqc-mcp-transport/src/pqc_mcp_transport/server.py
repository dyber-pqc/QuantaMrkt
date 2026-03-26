"""PQC-secured MCP server that verifies incoming signatures and signs responses."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Awaitable

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.audit import AuditLog
from pqc_mcp_transport.errors import (
    PeerNotAuthenticatedError,
    PQCTransportError,
    SessionExpiredError,
    SignatureVerificationError,
)
from pqc_mcp_transport.handshake import HandshakeRequest, HandshakeResponse, PQCHandshake
from pqc_mcp_transport.session import PQCSession
from pqc_mcp_transport.signer import MessageSigner


@dataclass
class ToolHandler:
    """A registered MCP tool handler."""

    name: str
    description: str
    handler: Callable[..., Awaitable[Any]]


class PQCMCPServer:
    """MCP server that verifies PQC signatures on incoming calls and signs all responses."""

    def __init__(
        self,
        identity: AgentIdentity,
        require_auth: bool = True,
    ) -> None:
        self.identity = identity
        self.signer = MessageSigner(identity)
        self._tools: dict[str, ToolHandler] = {}
        self._sessions: dict[str, PQCSession] = {}
        self._require_auth = require_auth
        self.audit = AuditLog()

    def tool(self, name: str, description: str = "") -> Callable:
        """Decorator to register an async tool handler."""

        def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            self._tools[name] = ToolHandler(
                name=name, description=description, handler=func
            )
            return func

        return decorator

    def get_tool_list(self) -> list[dict]:
        """Return a list of registered tools and their descriptions."""
        return [
            {"name": t.name, "description": t.description} for t in self._tools.values()
        ]

    async def handle_handshake(self, request_data: dict) -> dict:
        """Handle a PQC handshake initiation and return the response dict."""
        request = HandshakeRequest.from_dict(request_data)
        response = PQCHandshake.respond(request, self.identity)

        # Create a server-side session
        from quantumshield.core.algorithms import SignatureAlgorithm

        session = PQCSession(
            session_id=response.session_id,
            local_identity=self.identity,
            peer_did=request.client_did,
            peer_public_key=bytes.fromhex(request.client_public_key),
            peer_algorithm=SignatureAlgorithm(request.algorithm),
        )
        self._sessions[response.session_id] = session

        session.log_operation(
            op_type="handshake",
            method=None,
            signer_did=request.client_did,
            verified=True,
            signature_hex=request.signature,
            algorithm=request.algorithm,
            details="Handshake accepted",
        )

        return response.to_dict()

    async def handle_request(self, raw_message: dict) -> dict:
        """Process an incoming MCP request with PQC verification.

        Returns a signed JSON-RPC response dict.
        """
        # Check if it is a handshake request
        if raw_message.get("type") == "pqc_handshake_request":
            return await self.handle_handshake(raw_message)

        # Verify PQC signature
        if self._require_auth:
            pqc = raw_message.get("_pqc")
            if not pqc:
                return self._error_response(
                    raw_message.get("id"),
                    -32600,
                    "Missing _pqc signature envelope",
                )

            vr = MessageSigner.verify_message(raw_message)
            if not vr.valid:
                raise SignatureVerificationError(
                    f"Request signature verification failed: {vr.error}"
                )

            # Check session
            session_id = pqc.get("session_id")
            session = self._sessions.get(session_id) if session_id else None
            if session and not session.is_valid():
                raise SessionExpiredError("Session has expired")

            # Replay protection
            if session and vr.nonce:
                session.check_nonce(vr.nonce)

            if session:
                session.log_operation(
                    op_type="tool_call",
                    method=raw_message.get("method", ""),
                    signer_did=vr.signer_did or "unknown",
                    verified=True,
                    signature_hex=pqc.get("signature", ""),
                    algorithm=vr.algorithm or "",
                )

        # Strip PQC envelope for processing
        clean = MessageSigner.strip_pqc(raw_message)
        method = clean.get("method", "")
        msg_id = clean.get("id")
        params = clean.get("params", {})

        # Handle tools/list
        if method == "tools/list":
            result = {"tools": self.get_tool_list()}
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result,
            }
            return self.signer.sign_message(response)

        # Handle tools/call
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            handler = self._tools.get(tool_name)

            if handler is None:
                return self.signer.sign_message(
                    self._error_response(msg_id, -32601, f"Unknown tool: {tool_name}")
                )

            try:
                result = await handler.handler(**arguments)
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": result},
                }
            except Exception as exc:
                response = self._error_response(
                    msg_id, -32000, f"Tool error: {exc}"
                )

            return self.signer.sign_message(response)

        return self.signer.sign_message(
            self._error_response(msg_id, -32601, f"Unknown method: {method}")
        )

    @staticmethod
    def _error_response(msg_id: Any, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }

    async def run(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        """Run a simple async HTTP server.

        This is a minimal server suitable for development and examples.
        For production, use :class:`PQCMiddleware` with an ASGI framework.
        """
        server = await asyncio.start_server(
            lambda r, w: self._handle_connection(r, w),
            host,
            port,
        )
        async with server:
            await server.serve_forever()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single HTTP connection (minimal HTTP/1.1 parser)."""
        try:
            # Read request line and headers
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return

            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    key, value = line.decode("utf-8").split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # Read body
            content_length = int(headers.get("content-length", "0"))
            body = await reader.read(content_length) if content_length > 0 else b""

            # Parse path
            parts = request_line.decode("utf-8").split()
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            if method == "POST" and body:
                request_data = json.loads(body)

                if path == "/handshake":
                    response_data = await self.handle_handshake(request_data)
                else:
                    response_data = await self.handle_request(request_data)

                response_body = json.dumps(response_data).encode("utf-8")
                status = "200 OK"
            else:
                response_body = b'{"status": "PQC MCP Server running"}'
                status = "200 OK"

            # Write HTTP response
            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                f"\r\n"
            ).encode("utf-8") + response_body

            writer.write(response)
            await writer.drain()
        except Exception:
            error_body = b'{"error": "Internal server error"}'
            error_response = (
                f"HTTP/1.1 500 Internal Server Error\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(error_body)}\r\n"
                f"\r\n"
            ).encode("utf-8") + error_body
            writer.write(error_response)
            await writer.drain()
        finally:
            writer.close()
