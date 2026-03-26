"""Tests for MessageSigner — signing, verification, and canonicalization."""

from __future__ import annotations

import copy

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.signer import MessageSigner, VerificationResult


class TestCanonicalize:
    def test_canonicalize_deterministic(self, sample_tool_call: dict) -> None:
        """Canonicalization of the same message always yields the same bytes."""
        a = MessageSigner.canonicalize(sample_tool_call)
        b = MessageSigner.canonicalize(sample_tool_call)
        assert a == b

        # Insertion order shouldn't matter
        reordered = dict(reversed(list(sample_tool_call.items())))
        c = MessageSigner.canonicalize(reordered)
        assert a == c

    def test_canonicalize_strips_pqc(self, sample_tool_call: dict) -> None:
        """The _pqc field is excluded from the canonical form."""
        with_pqc = dict(sample_tool_call)
        with_pqc["_pqc"] = {"signature": "deadbeef"}
        canon_with = MessageSigner.canonicalize(with_pqc)
        canon_without = MessageSigner.canonicalize(sample_tool_call)
        assert canon_with == canon_without


class TestSignAndVerify:
    def test_sign_message_adds_pqc_envelope(
        self, message_signer: MessageSigner, sample_tool_call: dict
    ) -> None:
        signed = message_signer.sign_message(sample_tool_call)
        assert "_pqc" in signed
        pqc = signed["_pqc"]
        assert "signer_did" in pqc
        assert "algorithm" in pqc
        assert "timestamp" in pqc
        assert "nonce" in pqc
        assert "signature" in pqc
        assert "public_key" in pqc

    def test_verify_valid_signature(
        self, message_signer: MessageSigner, sample_tool_call: dict
    ) -> None:
        signed = message_signer.sign_message(sample_tool_call)
        result = MessageSigner.verify_message(signed)
        assert result.valid is True
        assert result.signer_did == message_signer.identity.did

    def test_verify_tampered_message_fails(
        self, message_signer: MessageSigner, sample_tool_call: dict
    ) -> None:
        signed = message_signer.sign_message(sample_tool_call)
        # Tamper with the payload
        signed["id"] = "tampered"
        result = MessageSigner.verify_message(signed)
        assert result.valid is False

    def test_verify_wrong_key_fails(
        self,
        message_signer: MessageSigner,
        server_identity: AgentIdentity,
        sample_tool_call: dict,
    ) -> None:
        signed = message_signer.sign_message(sample_tool_call)
        # Replace the public key with the server's key (mismatch)
        signed["_pqc"]["public_key"] = server_identity.signing_keypair.public_key.hex()
        result = MessageSigner.verify_message(signed)
        assert result.valid is False

    def test_verify_no_pqc_envelope(self, sample_tool_call: dict) -> None:
        result = MessageSigner.verify_message(sample_tool_call)
        assert result.valid is False
        assert result.error == "No _pqc envelope"


class TestStripPQC:
    def test_strip_pqc_removes_envelope(
        self, message_signer: MessageSigner, sample_tool_call: dict
    ) -> None:
        signed = message_signer.sign_message(sample_tool_call)
        stripped = MessageSigner.strip_pqc(signed)
        assert "_pqc" not in stripped
        # Original fields should still be there
        assert stripped["jsonrpc"] == "2.0"
        assert stripped["method"] == "tools/call"


class TestNonce:
    def test_nonce_uniqueness(
        self, message_signer: MessageSigner, sample_tool_call: dict
    ) -> None:
        """Each signed message gets a unique nonce."""
        signed1 = message_signer.sign_message(sample_tool_call)
        signed2 = message_signer.sign_message(sample_tool_call)
        assert signed1["_pqc"]["nonce"] != signed2["_pqc"]["nonce"]
