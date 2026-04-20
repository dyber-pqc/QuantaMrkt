"""Pytest fixtures for pqc-agent-wallet."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_agent_wallet import Wallet


@pytest.fixture
def owner() -> AgentIdentity:
    return AgentIdentity.create("test-agent")


@pytest.fixture
def wallet_path(tmp_path) -> str:
    return str(tmp_path / "agent.wallet")


@pytest.fixture
def open_wallet(wallet_path, owner) -> Wallet:
    w = Wallet.create_with_passphrase(wallet_path, "correct-horse-battery", owner)
    w.put("openai_api_key", "sk-test-openai", service="openai")
    w.put("postgres_password", "db-pass-123", service="postgres", scheme="password")
    return w
