"""Tests for PQC mutual authentication handshake."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.errors import HandshakeError
from pqc_mcp_transport.handshake import (
    HandshakeRequest,
    HandshakeResponse,
    PQCHandshake,
)
from pqc_mcp_transport.session import PQCSession


class TestHandshakeInitiate:
    def test_initiate_creates_valid_request(
        self, client_identity: AgentIdentity
    ) -> None:
        request, nonce = PQCHandshake.initiate(client_identity)
        assert isinstance(request, HandshakeRequest)
        assert request.client_did == client_identity.did
        assert request.client_public_key == client_identity.signing_keypair.public_key.hex()
        assert len(nonce) == 32  # 16 bytes hex
        assert request.nonce == nonce
        assert len(request.signature) > 0


class TestHandshakeRespond:
    def test_respond_verifies_client(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        request, _nonce = PQCHandshake.initiate(client_identity)
        response = PQCHandshake.respond(request, server_identity)
        assert isinstance(response, HandshakeResponse)
        assert response.server_did == server_identity.did
        assert response.client_nonce == request.nonce
        assert len(response.session_id) > 0

    def test_respond_rejects_invalid_signature(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        request, _nonce = PQCHandshake.initiate(client_identity)
        # Tamper with the signature
        request.signature = "00" * 64
        with pytest.raises(HandshakeError, match="Client handshake signature"):
            PQCHandshake.respond(request, server_identity)


class TestHandshakeComplete:
    def test_complete_creates_session(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        request, nonce = PQCHandshake.initiate(client_identity)
        response = PQCHandshake.respond(request, server_identity)
        session = PQCHandshake.complete(response, client_identity, nonce)
        assert isinstance(session, PQCSession)
        assert session.session_id == response.session_id
        assert session.peer_did == server_identity.did

    def test_complete_rejects_invalid_server_signature(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        request, nonce = PQCHandshake.initiate(client_identity)
        response = PQCHandshake.respond(request, server_identity)
        # Tamper with the server signature
        response.signature = "00" * 64
        with pytest.raises(HandshakeError, match="Server handshake signature"):
            PQCHandshake.complete(response, client_identity, nonce)

    def test_complete_rejects_wrong_nonce(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        request, nonce = PQCHandshake.initiate(client_identity)
        response = PQCHandshake.respond(request, server_identity)
        with pytest.raises(HandshakeError, match="correct client nonce"):
            PQCHandshake.complete(response, client_identity, "wrong_nonce")


class TestFullRoundTrip:
    def test_full_handshake_round_trip(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        """End-to-end handshake: initiate -> respond -> complete."""
        request, nonce = PQCHandshake.initiate(client_identity)
        response = PQCHandshake.respond(request, server_identity)
        session = PQCHandshake.complete(response, client_identity, nonce)

        assert session.is_valid()
        assert session.peer_did == server_identity.did
        assert session.local_identity.did == client_identity.did
        assert session.peer_public_key == server_identity.signing_keypair.public_key
