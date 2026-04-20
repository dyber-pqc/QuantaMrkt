"""Exception hierarchy for pqc-agent-wallet."""

from __future__ import annotations


class WalletError(Exception):
    """Base for all wallet errors."""


class WalletLockedError(WalletError):
    """Operation requires an unlocked wallet; call unlock() first."""


class CredentialNotFoundError(WalletError):
    """Named credential does not exist in the wallet."""


class InvalidPassphraseError(WalletError):
    """Passphrase failed to derive a valid unlock key."""


class TamperedWalletError(WalletError):
    """Wallet file signature or MAC failed verification."""


class WalletFormatError(WalletError):
    """Wallet file is malformed or of incompatible version."""
