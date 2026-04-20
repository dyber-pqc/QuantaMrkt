"""Tests for GovernanceAuditLog."""

from __future__ import annotations

from pqc_ai_governance import (
    ConsensusResult,
    GovernanceAuditLog,
    GovernanceProposal,
    ProposalKind,
)


def test_log_proposal_created_appends() -> None:
    log = GovernanceAuditLog()
    prop = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="did:pqaid:model-x",
        title="x",
        proposer_did="did:pqaid:alice",
    )
    log.log_proposal_created(prop)
    assert len(log) == 1
    entries = log.entries()
    assert entries[0].operation == "proposal_created"
    assert entries[0].proposal_id == prop.proposal_id
    assert entries[0].kind == "authorize-model"


def test_log_consensus_reached_captures_decision_and_weights() -> None:
    log = GovernanceAuditLog()
    result = ConsensusResult(
        proposal_id="p1",
        proposal_hash="h",
        decision="passed",
        reason="quorum met",
        approve_weight=4,
        reject_weight=1,
        abstain_weight=0,
        total_weight=5,
        included_vote_ids=["v1", "v2", "v3", "v4", "v5"],
        signer_did="did:pqaid:alice",
    )
    log.log_consensus_reached(result)
    entry = log.entries()[0]
    assert entry.operation == "consensus_reached"
    assert entry.decision == "passed"
    assert entry.details["approve_weight"] == 4
    assert entry.details["reject_weight"] == 1
    assert entry.details["vote_count"] == 5


def test_filter_by_operation() -> None:
    log = GovernanceAuditLog()
    prop = GovernanceProposal.create(
        kind=ProposalKind.AUTHORIZE_MODEL,
        subject_id="x",
        title="x",
        proposer_did="did:pqaid:alice",
    )
    log.log_proposal_created(prop)
    log.log_node_added(did="did:pqaid:bob", name="bob", weight=1)
    log.log_node_added(did="did:pqaid:carol", name="carol", weight=1)
    assert len(log) == 3
    adds = log.entries(operation="node_added")
    assert len(adds) == 2
    assert all(e.operation == "node_added" for e in adds)
