"""Tests for PQCMCPClient — message signing and response verification."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.client import PQCMCPClient
from pqc_mcp_transport.signer import MessageSigner


class TestClientSigning:
    def test_client_signs_tool_call(
        self, client_identity: AgentIdentity
    ) -> None:
        """The client's signer produces valid PQC-signed messages."""
        client = PQCMCPClient(
            identity=client_identity,
            server_url="http://localhost:8080",
        )
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-1",
            "params": {"name": "greet", "arguments": {"name": "World"}},
        }
        signed = client.signer.sign_message(message)
        assert "_pqc" in signed
        result = MessageSigner.verify_message(signed)
        assert result.valid is True
        assert result.signer_did == client_identity.did

    def test_client_verifies_response(
        self,
        client_identity: AgentIdentity,
        server_identity: AgentIdentity,
        sample_response: dict,
    ) -> None:
        """The client can verify a server-signed response."""
        server_signer = MessageSigner(server_identity)
        signed_response = server_signer.sign_message(sample_response)

        result = MessageSigner.verify_message(signed_response)
        assert result.valid is True
        assert result.signer_did == server_identity.did
