"""PQC Agent Credential Wallet - Quantum-resistant vault for AI-agent credentials."""

from pqc_agent_wallet.audit import WalletAuditEntry, WalletAuditLog
from pqc_agent_wallet.credential import Credential, CredentialMetadata
from pqc_agent_wallet.errors import (
    CredentialNotFoundError,
    InvalidPassphraseError,
    TamperedWalletError,
    WalletError,
    WalletFormatError,
    WalletLockedError,
)
from pqc_agent_wallet.kdf import derive_key_from_passphrase
from pqc_agent_wallet.vault import Wallet

__version__ = "0.1.0"
__all__ = [
    "Wallet",
    "Credential",
    "CredentialMetadata",
    "WalletAuditEntry",
    "WalletAuditLog",
    "derive_key_from_passphrase",
    "WalletError",
    "WalletLockedError",
    "CredentialNotFoundError",
    "InvalidPassphraseError",
    "TamperedWalletError",
    "WalletFormatError",
]
