"""Tests for GovernanceProposal."""

from __future__ import annotations

import time

from pqc_ai_governance import GovernanceProposal, ProposalKind, ProposalStatus


def test_create_populates_fields() -> None:
    prop = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="did:pqaid:abc",
        title="Authorize abc",
        proposer_did="did:pqaid:alice",
    )
    assert prop.proposal_id.startswith("urn:pqc-gov-prop:")
    assert prop.kind == ProposalKind.AUTHORIZE_MODEL
    assert prop.status == ProposalStatus.OPEN
    assert prop.created_at != ""
    assert prop.expires_at != ""
    assert prop.signature == ""


def test_proposal_hash_is_deterministic() -> None:
    prop = GovernanceProposal.create(
        kind=ProposalKind.UPDATE_POLICY,
        subject_id="policy-1",
        title="Raise rate limit",
        proposer_did="did:pqaid:alice",
        parameters={"max_rate_qps": 100, "window": "1m"},
    )
    h1 = prop.proposal_hash()
    h2 = prop.proposal_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_is_expired_after_ttl_zero() -> None:
    prop = GovernanceProposal.create(
        kind=ProposalKind.EMERGENCY_FREEZE,
        subject_id="*",
        title="freeze now",
        proposer_did="did:pqaid:alice",
        ttl_seconds=0,
    )
    time.sleep(0.01)
    assert prop.is_expired() is True


def test_to_dict_from_dict_roundtrip() -> None:
    original = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_AGENT,
        subject_id="did:pqaid:agent-x",
        title="Authorize agent x",
        proposer_did="did:pqaid:alice",
        description="grant scope",
        parameters={"scope": ["read", "write"]},
    )
    d = original.to_dict()
    restored = GovernanceProposal.from_dict(d)
    assert restored.proposal_id == original.proposal_id
    assert restored.kind == original.kind
    assert restored.subject_id == original.subject_id
    assert restored.parameters == original.parameters
    assert restored.proposal_hash() == original.proposal_hash()


def test_canonical_bytes_is_deterministic() -> None:
    prop = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="did:pqaid:abc",
        title="x",
        proposer_did="did:pqaid:alice",
        parameters={"b": 2, "a": 1},
    )
    b1 = prop.canonical_bytes()
    b2 = prop.canonical_bytes()
    assert b1 == b2
    # Keys should be alphabetised deterministically
    assert b'"a":1' in b1
    assert b1.index(b'"a":1') < b1.index(b'"b":2')
