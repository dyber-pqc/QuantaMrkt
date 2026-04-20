"""Integration helpers for agent frameworks (LangChain, AutoGen, CrewAI)."""

from pqc_agent_wallet.integrations.env_shim import install_env_shim, uninstall_env_shim
from pqc_agent_wallet.integrations.langchain import (
    make_langchain_secret_provider,
    walletize_env,
)

__all__ = [
    "make_langchain_secret_provider",
    "walletize_env",
    "install_env_shim",
    "uninstall_env_shim",
]
