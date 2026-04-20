"""Shared test fixtures for pqc-audit-log-fs."""

from __future__ import annotations

import os
import random
from collections.abc import Callable
from pathlib import Path

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.event import InferenceEvent


@pytest.fixture
def signer_identity() -> AgentIdentity:
    """A fresh AgentIdentity for signing segments."""
    return AgentIdentity.create(
        name="test-audit-signer",
        capabilities=["audit.sign"],
    )


@pytest.fixture
def tmp_log_dir(tmp_path: Path) -> str:
    """A clean log directory under pytest's tmp_path."""
    d = tmp_path / "log"
    os.makedirs(d, exist_ok=True)
    return str(d)


@pytest.fixture
def event_factory() -> Callable[..., InferenceEvent]:
    """Factory that builds random InferenceEvents with optional overrides."""
    rng = random.Random(1234)

    def _make(
        *,
        decision_label: str | None = None,
        model_version: str = "1.0.0",
    ) -> InferenceEvent:
        # Random input / output blobs so hashes differ between calls
        inp = rng.randbytes(32)
        out = rng.randbytes(32)
        return InferenceEvent.create(
            model_did="did:pqaid:test-model",
            model_version=model_version,
            input_bytes=inp,
            output_bytes=out,
            reasoning_bytes=b"step-by-step",
            decision_type="classification",
            decision_label=decision_label or rng.choice(["approve", "deny", "review"]),
            actor_did="did:pqaid:test-user",
            session_id=f"sess-{rng.randint(1, 9999)}",
            metadata={"test": True},
        )

    return _make
