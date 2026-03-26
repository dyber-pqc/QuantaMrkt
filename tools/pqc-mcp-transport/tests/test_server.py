"""Tests for PQCMCPServer — tool registration, verification, signing."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.server import PQCMCPServer
from pqc_mcp_transport.signer import MessageSigner


@pytest.fixture
def server(server_identity: AgentIdentity) -> PQCMCPServer:
    srv = PQCMCPServer(identity=server_identity, require_auth=True)

    @srv.tool("greet", description="Greet someone")
    async def greet(name: str) -> str:
        return f"Hello, {name}!"

    return srv


class TestToolRegistration:
    def test_server_registers_tool(self, server: PQCMCPServer) -> None:
        tools = server.get_tool_list()
        assert len(tools) == 1
        assert tools[0]["name"] == "greet"
        assert tools[0]["description"] == "Greet someone"


@pytest.mark.asyncio
class TestRequestHandling:
    async def test_server_verifies_incoming_call(
        self,
        server: PQCMCPServer,
        client_identity: AgentIdentity,
        server_identity: AgentIdentity,
    ) -> None:
        """A properly signed request is accepted and produces a signed response."""
        # First do a handshake
        from pqc_mcp_transport.handshake import PQCHandshake

        request, nonce = PQCHandshake.initiate(client_identity)
        hs_response = await server.handle_handshake(request.to_dict())
        session_id = hs_response["session_id"]

        # Now send a signed tool call
        signer = MessageSigner(client_identity)
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "req-1",
            "params": {"name": "greet", "arguments": {"name": "Alice"}},
        }
        signed = signer.sign_message(message)
        signed["_pqc"]["session_id"] = session_id

        response = await server.handle_request(signed)
        assert "_pqc" in response
        # Verify the server's response signature
        vr = MessageSigner.verify_message(response)
        assert vr.valid is True
        assert vr.signer_did == server_identity.did

        stripped = MessageSigner.strip_pqc(response)
        assert stripped["result"]["content"] == "Hello, Alice!"

    async def test_server_rejects_unsigned_call(
        self, server: PQCMCPServer
    ) -> None:
        """An unsigned request is rejected when require_auth is True."""
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "req-2",
            "params": {"name": "greet", "arguments": {"name": "Bob"}},
        }
        response = await server.handle_request(message)
        # Should get an error response (no _pqc signature is also not signed)
        assert "error" in response
        assert response["error"]["code"] == -32600

    async def test_server_signs_response(
        self,
        server: PQCMCPServer,
        client_identity: AgentIdentity,
        server_identity: AgentIdentity,
    ) -> None:
        """Every response from the server carries a _pqc envelope."""
        from pqc_mcp_transport.handshake import PQCHandshake

        request, nonce = PQCHandshake.initiate(client_identity)
        hs_response = await server.handle_handshake(request.to_dict())
        session_id = hs_response["session_id"]

        signer = MessageSigner(client_identity)
        message = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": "req-3",
        }
        signed = signer.sign_message(message)
        signed["_pqc"]["session_id"] = session_id

        response = await server.handle_request(signed)
        assert "_pqc" in response
        assert response["_pqc"]["signer_did"] == server_identity.did
