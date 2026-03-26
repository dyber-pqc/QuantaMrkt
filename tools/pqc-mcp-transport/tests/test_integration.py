"""End-to-end integration tests — full handshake + tool call flow."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.handshake import PQCHandshake
from pqc_mcp_transport.server import PQCMCPServer
from pqc_mcp_transport.signer import MessageSigner


@pytest.fixture
def integration_server(server_identity: AgentIdentity) -> PQCMCPServer:
    srv = PQCMCPServer(identity=server_identity, require_auth=True)

    @srv.tool("add", description="Add two numbers")
    async def add(a: float, b: float) -> float:
        return a + b

    @srv.tool("echo", description="Echo input")
    async def echo(message: str) -> str:
        return message

    return srv


@pytest.mark.asyncio
class TestIntegration:
    async def test_client_server_handshake_and_tool_call(
        self,
        integration_server: PQCMCPServer,
        client_identity: AgentIdentity,
        server_identity: AgentIdentity,
    ) -> None:
        """Full round-trip: handshake -> tool call -> verified response."""
        # Step 1: Client initiates handshake
        hs_request, nonce = PQCHandshake.initiate(client_identity)

        # Step 2: Server responds to handshake
        hs_response_dict = await integration_server.handle_handshake(
            hs_request.to_dict()
        )

        # Step 3: Client completes handshake
        from pqc_mcp_transport.handshake import HandshakeResponse

        hs_response = HandshakeResponse.from_dict(hs_response_dict)
        session = PQCHandshake.complete(hs_response, client_identity, nonce)
        assert session.is_valid()
        assert session.peer_did == server_identity.did

        # Step 4: Client sends a signed tool call
        client_signer = MessageSigner(client_identity)
        call_msg = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "int-1",
            "params": {"name": "add", "arguments": {"a": 3.0, "b": 4.0}},
        }
        signed_call = client_signer.sign_message(call_msg)
        signed_call["_pqc"]["session_id"] = session.session_id

        # Step 5: Server processes, verifies, and returns signed response
        response = await integration_server.handle_request(signed_call)
        assert "_pqc" in response

        # Step 6: Client verifies server response
        vr = MessageSigner.verify_message(response)
        assert vr.valid is True
        assert vr.signer_did == server_identity.did

        stripped = MessageSigner.strip_pqc(response)
        assert stripped["result"]["content"] == 7.0

    async def test_mutual_authentication(
        self,
        integration_server: PQCMCPServer,
        client_identity: AgentIdentity,
        server_identity: AgentIdentity,
    ) -> None:
        """Both sides verify each other's signatures throughout the flow."""
        # Handshake
        hs_request, nonce = PQCHandshake.initiate(client_identity)
        hs_response_dict = await integration_server.handle_handshake(
            hs_request.to_dict()
        )
        from pqc_mcp_transport.handshake import HandshakeResponse

        hs_response = HandshakeResponse.from_dict(hs_response_dict)
        session = PQCHandshake.complete(hs_response, client_identity, nonce)

        # Client signs a request — server verifies the client's identity
        client_signer = MessageSigner(client_identity)
        call_msg = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "int-2",
            "params": {"name": "echo", "arguments": {"message": "mutual-auth-test"}},
        }
        signed_call = client_signer.sign_message(call_msg)
        signed_call["_pqc"]["session_id"] = session.session_id

        # Verify client signature independently
        client_vr = MessageSigner.verify_message(signed_call)
        assert client_vr.valid is True
        assert client_vr.signer_did == client_identity.did

        # Server processes and signs response
        response = await integration_server.handle_request(signed_call)

        # Verify server signature independently
        server_vr = MessageSigner.verify_message(response)
        assert server_vr.valid is True
        assert server_vr.signer_did == server_identity.did

        stripped = MessageSigner.strip_pqc(response)
        assert stripped["result"]["content"] == "mutual-auth-test"
