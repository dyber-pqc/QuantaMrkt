"""Tests for LangChain + env_shim integrations."""

from __future__ import annotations

import os

import pytest

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.integrations import (
    install_env_shim,
    make_langchain_secret_provider,
    walletize_env,
)
from pqc_agent_wallet.integrations.env_shim import uninstall_env_shim


def test_make_langchain_provider_returns_value(open_wallet: Wallet) -> None:
    provider = make_langchain_secret_provider(open_wallet)
    assert provider("openai_api_key") == "sk-test-openai"


def test_langchain_provider_raises_on_missing(open_wallet: Wallet) -> None:
    provider = make_langchain_secret_provider(open_wallet)
    with pytest.raises(KeyError):
        provider("does-not-exist")


def test_env_shim_falls_back_to_wallet(open_wallet: Wallet) -> None:
    # Make sure the env var is not already set.
    os.environ.pop("openai_api_key", None)
    try:
        install_env_shim(open_wallet)
        assert os.getenv("openai_api_key") == "sk-test-openai"
        # Default still returned when credential is missing
        assert os.getenv("totally_missing_thing", "default-val") == "default-val"
    finally:
        uninstall_env_shim()


def test_env_shim_prefers_real_env(open_wallet: Wallet) -> None:
    os.environ["openai_api_key"] = "real-env-value"
    try:
        install_env_shim(open_wallet)
        assert os.getenv("openai_api_key") == "real-env-value"
    finally:
        uninstall_env_shim()
        os.environ.pop("openai_api_key", None)


def test_walletize_env_resolves_mapping(open_wallet: Wallet) -> None:
    mapping = {
        "OPENAI_API_KEY": "openai_api_key",
        "POSTGRES_PASSWORD": "postgres_password",
    }
    resolved = walletize_env(open_wallet, mapping)
    assert resolved == {
        "OPENAI_API_KEY": "sk-test-openai",
        "POSTGRES_PASSWORD": "db-pass-123",
    }
