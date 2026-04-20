"""Install an os.environ shim that falls back to the wallet for missing keys.

Usage:
    from pqc_agent_wallet.integrations.env_shim import install_env_shim
    install_env_shim(wallet)

    # Now any code that does os.getenv('OPENAI_API_KEY') will fall back
    # to wallet.get('openai_api_key') if it isn't in os.environ.
"""

from __future__ import annotations

import os

from pqc_agent_wallet.errors import CredentialNotFoundError, WalletLockedError
from pqc_agent_wallet.vault import Wallet

_original_getenv = None


def install_env_shim(wallet: Wallet) -> None:
    """Monkey-patch os.getenv to fall back to the wallet."""
    global _original_getenv
    if _original_getenv is not None:
        return  # already installed
    _original_getenv = os.getenv

    def shim(key: str, default: str | None = None) -> str | None:
        val = _original_getenv(key, None) if _original_getenv else None
        if val is not None:
            return val
        if not wallet.is_unlocked:
            return default
        try:
            return wallet.get(key.lower())
        except (CredentialNotFoundError, WalletLockedError):
            return default

    os.getenv = shim  # type: ignore[assignment]


def uninstall_env_shim() -> None:
    """Restore the original os.getenv."""
    global _original_getenv
    if _original_getenv is None:
        return
    os.getenv = _original_getenv  # type: ignore[assignment]
    _original_getenv = None
