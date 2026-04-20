"""Tests for AuthorizationChain and AuthorizationGrant."""

from __future__ import annotations

import pytest

from pqc_ai_governance import (
    AuthorizationChain,
    AuthorizationGrant,
    ConsensusResult,
    GovernanceError,
    ProposalKind,
)


def _result(decision: str) -> ConsensusResult:
    return ConsensusResult(
        proposal_id="p",
        proposal_hash="h",
        decision=decision,
        reason="",
        approve_weight=0,
        reject_weight=0,
        abstain_weight=0,
        total_weight=0,
    )


def test_chain_add_wrong_subject_raises() -> None:
    chain = AuthorizationChain(subject_id="did:pqaid:model-x")
    grant = AuthorizationGrant(
        subject_id="did:pqaid:model-y",
        kind=ProposalKind.AUTHORIZE_MODEL,
        result=_result("passed"),
    )
    with pytest.raises(GovernanceError):
        chain.add(grant)


def test_is_authorized_true_after_authorize_model_passes() -> None:
    chain = AuthorizationChain(subject_id="did:pqaid:model-x")
    chain.add(
        AuthorizationGrant(
            subject_id="did:pqaid:model-x",
            kind=ProposalKind.AUTHORIZE_MODEL,
            result=_result("passed"),
        )
    )
    assert chain.is_authorized(ProposalKind.AUTHORIZE_MODEL) is True


def test_is_authorized_false_after_subsequent_revoke() -> None:
    chain = AuthorizationChain(subject_id="did:pqaid:model-x")
    chain.add(
        AuthorizationGrant(
            subject_id="did:pqaid:model-x",
            kind=ProposalKind.AUTHORIZE_MODEL,
            result=_result("passed"),
        )
    )
    chain.add(
        AuthorizationGrant(
            subject_id="did:pqaid:model-x",
            kind=ProposalKind.REVOKE_MODEL,
            result=_result("passed"),
        )
    )
    assert chain.is_authorized(ProposalKind.AUTHORIZE_MODEL) is False


def test_is_authorized_respects_only_passed_grants() -> None:
    chain = AuthorizationChain(subject_id="did:pqaid:model-x")
    # Rejected authorization should not authorize anything
    chain.add(
        AuthorizationGrant(
            subject_id="did:pqaid:model-x",
            kind=ProposalKind.AUTHORIZE_MODEL,
            result=_result("rejected"),
        )
    )
    assert chain.is_authorized(ProposalKind.AUTHORIZE_MODEL) is False
    # A rejected revoke should not undo a passed authorize
    chain.add(
        AuthorizationGrant(
            subject_id="did:pqaid:model-x",
            kind=ProposalKind.AUTHORIZE_MODEL,
            result=_result("passed"),
        )
    )
    chain.add(
        AuthorizationGrant(
            subject_id="did:pqaid:model-x",
            kind=ProposalKind.REVOKE_MODEL,
            result=_result("rejected"),
        )
    )
    assert chain.is_authorized(ProposalKind.AUTHORIZE_MODEL) is True
