"""Tests for PQCSession — expiry, replay protection, audit logging."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.errors import ReplayAttackError
from pqc_mcp_transport.session import PQCSession


def _make_session(
    client_identity: AgentIdentity,
    server_identity: AgentIdentity,
    expires_delta: timedelta | None = None,
) -> PQCSession:
    """Helper to create a session without going through the handshake."""
    now = datetime.now(timezone.utc)
    return PQCSession(
        session_id="test-session-001",
        local_identity=client_identity,
        peer_did=server_identity.did,
        peer_public_key=server_identity.signing_keypair.public_key,
        peer_algorithm=server_identity.signing_keypair.algorithm,
        created_at=now,
        expires_at=now + (expires_delta or timedelta(hours=1)),
    )


class TestSessionValidity:
    def test_session_valid_initially(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        session = _make_session(client_identity, server_identity)
        assert session.is_valid() is True

    def test_session_expires(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        session = _make_session(
            client_identity, server_identity, expires_delta=timedelta(seconds=-1)
        )
        assert session.is_valid() is False


class TestReplayProtection:
    def test_nonce_replay_protection(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        session = _make_session(client_identity, server_identity)
        assert session.check_nonce("nonce-1") is True
        with pytest.raises(ReplayAttackError):
            session.check_nonce("nonce-1")

    def test_different_nonces_ok(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        session = _make_session(client_identity, server_identity)
        assert session.check_nonce("nonce-1") is True
        assert session.check_nonce("nonce-2") is True


class TestAuditLog:
    def test_audit_log_records_operations(
        self, client_identity: AgentIdentity, server_identity: AgentIdentity
    ) -> None:
        session = _make_session(client_identity, server_identity)
        assert len(session.get_audit_log()) == 0

        session.log_operation(
            op_type="tool_call",
            method="greet",
            signer_did=client_identity.did,
            verified=True,
            signature_hex="aabbccdd",
            algorithm="ML-DSA-65",
        )
        log = session.get_audit_log()
        assert len(log) == 1
        assert log[0].operation == "tool_call"
        assert log[0].method == "greet"
        assert log[0].verified is True
