"""Tests for AccessPolicy / ArtifactPolicy."""

from __future__ import annotations

import pytest

from pqc_enclave_sdk import (
    AccessPolicy,
    ArtifactKind,
    ArtifactMetadata,
    ArtifactPolicy,
    PolicyViolationError,
)


def _meta(
    kind: ArtifactKind, bundle: str = "com.example.app"
) -> ArtifactMetadata:
    return ArtifactMetadata(
        artifact_id="id",
        name="n",
        kind=kind,
        app_bundle_id=bundle,
    )


def test_no_rule_allows_by_default() -> None:
    policy = AccessPolicy()
    policy.check(_meta(ArtifactKind.MODEL_WEIGHTS), "com.any.caller")


def test_allowed_bundle_ids_filters_callers() -> None:
    policy = AccessPolicy().add(
        ArtifactPolicy(
            kind=ArtifactKind.CREDENTIAL,
            allowed_bundle_ids=frozenset({"com.example.trusted"}),
        )
    )
    policy.check(_meta(ArtifactKind.CREDENTIAL), "com.example.trusted")


def test_empty_allow_list_without_biometric_allows() -> None:
    policy = AccessPolicy().add(
        ArtifactPolicy(
            kind=ArtifactKind.TOKENIZER,
            allowed_bundle_ids=frozenset(),
            require_biometric=False,
        )
    )
    # Empty allow-list means any bundle; check should not raise.
    policy.check(_meta(ArtifactKind.TOKENIZER), "com.random.bundle")


def test_check_raises_on_denied_caller() -> None:
    policy = AccessPolicy().add(
        ArtifactPolicy(
            kind=ArtifactKind.CREDENTIAL,
            allowed_bundle_ids=frozenset({"com.example.trusted"}),
        )
    )
    with pytest.raises(PolicyViolationError):
        policy.check(_meta(ArtifactKind.CREDENTIAL), "com.example.malicious")
