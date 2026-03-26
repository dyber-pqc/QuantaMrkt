"""PQC-secured MCP client that wraps tool calls with ML-DSA signatures."""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.errors import (
    HandshakeError,
    PeerNotAuthenticatedError,
    PQCTransportError,
    SessionExpiredError,
    SignatureVerificationError,
)
from pqc_mcp_transport.handshake import HandshakeRequest, HandshakeResponse, PQCHandshake
from pqc_mcp_transport.session import PQCSession
from pqc_mcp_transport.signer import MessageSigner


class PQCMCPClient:
    """Async MCP client that signs every request with ML-DSA and verifies responses."""

    def __init__(
        self,
        identity: AgentIdentity,
        server_url: str,
        verify_responses: bool = True,
    ) -> None:
        self.identity = identity
        self.server_url = server_url.rstrip("/")
        self.signer = MessageSigner(identity)
        self.session: PQCSession | None = None
        self._verify_responses = verify_responses
        self._http = httpx.AsyncClient()

    async def connect(self) -> PQCSession:
        """Perform a PQC handshake with the server and establish a session."""
        request, nonce = PQCHandshake.initiate(self.identity)

        resp = await self._http.post(
            f"{self.server_url}/handshake",
            json=request.to_dict(),
        )
        if resp.status_code != 200:
            raise HandshakeError(f"Handshake request failed: HTTP {resp.status_code}")

        response = HandshakeResponse.from_dict(resp.json())
        self.session = PQCHandshake.complete(response, self.identity, nonce)

        self.session.log_operation(
            op_type="handshake",
            method=None,
            signer_did=response.server_did,
            verified=True,
            signature_hex=response.signature,
            algorithm=response.algorithm,
            details="Handshake completed successfully",
        )
        return self.session

    def _require_session(self) -> PQCSession:
        if self.session is None:
            raise PeerNotAuthenticatedError("No active session. Call connect() first.")
        if not self.session.is_valid():
            raise SessionExpiredError("Session has expired. Reconnect.")
        return self.session

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict:
        """Call an MCP tool with a PQC-signed request.

        Returns the JSON-RPC result (unwrapped from the response envelope).
        """
        session = self._require_session()

        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": uuid.uuid4().hex,
            "params": {
                "name": name,
                "arguments": arguments or {},
            },
        }
        signed = self.signer.sign_message(message)
        signed["_pqc"]["session_id"] = session.session_id

        resp = await self._http.post(f"{self.server_url}/mcp", json=signed)
        if resp.status_code != 200:
            raise PQCTransportError(f"Tool call failed: HTTP {resp.status_code}")

        resp_data = resp.json()

        if self._verify_responses and "_pqc" in resp_data:
            vr = MessageSigner.verify_message(resp_data)
            session.last_response_verified = vr.valid
            session.log_operation(
                op_type="tool_response",
                method=name,
                signer_did=vr.signer_did or "unknown",
                verified=vr.valid,
                signature_hex=resp_data.get("_pqc", {}).get("signature", ""),
                algorithm=vr.algorithm or "",
            )
            if not vr.valid:
                raise SignatureVerificationError(
                    f"Server response signature invalid: {vr.error}"
                )
        else:
            session.last_response_verified = False

        session.log_operation(
            op_type="tool_call",
            method=name,
            signer_did=self.identity.did,
            verified=True,
            signature_hex=signed.get("_pqc", {}).get("signature", ""),
            algorithm=self.identity.signing_keypair.algorithm.value,
        )

        return MessageSigner.strip_pqc(resp_data)

    async def list_tools(self) -> list[dict]:
        """List available tools via a PQC-signed request."""
        session = self._require_session()

        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": uuid.uuid4().hex,
        }
        signed = self.signer.sign_message(message)
        signed["_pqc"]["session_id"] = session.session_id

        resp = await self._http.post(f"{self.server_url}/mcp", json=signed)
        if resp.status_code != 200:
            raise PQCTransportError(f"List tools failed: HTTP {resp.status_code}")

        resp_data = resp.json()

        if self._verify_responses and "_pqc" in resp_data:
            vr = MessageSigner.verify_message(resp_data)
            session.last_response_verified = vr.valid
            if not vr.valid:
                raise SignatureVerificationError(
                    f"Server response signature invalid: {vr.error}"
                )

        return MessageSigner.strip_pqc(resp_data).get("result", {}).get("tools", [])

    async def close(self) -> None:
        """Close the HTTP client and invalidate the session."""
        await self._http.aclose()
        self.session = None
