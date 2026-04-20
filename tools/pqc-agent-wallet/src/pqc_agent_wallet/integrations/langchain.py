"""LangChain-style secret provider.

LangChain (and many frameworks) accept a callable that returns secrets.
`make_langchain_secret_provider(wallet)` returns a callable compatible
with that pattern.
"""

from __future__ import annotations

from typing import Callable

from pqc_agent_wallet.errors import CredentialNotFoundError
from pqc_agent_wallet.vault import Wallet


def make_langchain_secret_provider(wallet: Wallet) -> Callable[[str], str]:
    """Return a callable `provider(name) -> str` that reads from the wallet."""

    def provider(name: str) -> str:
        try:
            return wallet.get(name)
        except CredentialNotFoundError as exc:
            raise KeyError(f"credential '{name}' not in wallet") from exc

    return provider


def walletize_env(wallet: Wallet, env_mapping: dict[str, str]) -> dict[str, str]:
    """Resolve a mapping of {env_name: credential_name} to real values from the wallet.

    Useful for bulk-populating framework configs that expect env-style strings.
    """
    out: dict[str, str] = {}
    for env_name, cred_name in env_mapping.items():
        out[env_name] = wallet.get(cred_name)
    return out
