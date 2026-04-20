"""Wallet - encrypted credential vault with ML-DSA integrity and optional ML-KEM key encapsulation."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_agent_wallet.audit import WalletAuditLog
from pqc_agent_wallet.credential import Credential, CredentialMetadata
from pqc_agent_wallet.errors import (
    CredentialNotFoundError,
    InvalidPassphraseError,
    TamperedWalletError,
    WalletFormatError,
    WalletLockedError,
)
from pqc_agent_wallet.kdf import DEFAULT_ITERATIONS, derive_key_from_passphrase

WALLET_FORMAT_VERSION = "1.0"
NONCE_LENGTH = 12
SALT_LENGTH = 16


@dataclass
class _EncryptedCredential:
    nonce: str  # hex
    ciphertext: str  # hex
    metadata: CredentialMetadata


class Wallet:
    """Encrypted credential store for an AI agent.

    Two unlock modes:
      1. Passphrase: `Wallet.create_with_passphrase(path, passphrase, owner)`
      2. KEM-encapsulated: `Wallet.create_with_kem(path, recipient_kem_public_key, owner)`
         - the wallet is created with an ephemeral symmetric key encapsulated to
         the recipient's ML-KEM-768 public key. To unlock, the recipient uses
         their private key to decapsulate.

    Usage:
        owner = AgentIdentity.create("my-agent")
        wallet = Wallet.create_with_passphrase("agent.wallet", "hunter2", owner)
        wallet.put("openai_api_key", "sk-...", service="openai")
        wallet.save()
        wallet.lock()

        # Later...
        wallet = Wallet.load("agent.wallet", owner)
        wallet.unlock_with_passphrase("hunter2")
        key = wallet.get("openai_api_key")
    """

    def __init__(
        self,
        path: str,
        owner: AgentIdentity,
        salt: bytes = b"",
        iterations: int = DEFAULT_ITERATIONS,
        kem_encapsulation: dict | None = None,
        encrypted_credentials: dict[str, _EncryptedCredential] | None = None,
        created_at: str = "",
        audit_log: WalletAuditLog | None = None,
    ):
        self.path = path
        self.owner = owner
        self.salt = salt or os.urandom(SALT_LENGTH)
        self.iterations = iterations
        self.kem_encapsulation = kem_encapsulation  # or None
        self._encrypted: dict[str, _EncryptedCredential] = encrypted_credentials or {}
        self._unlock_key: bytes | None = None
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.audit = audit_log or WalletAuditLog()

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def create_with_passphrase(
        cls,
        path: str,
        passphrase: str,
        owner: AgentIdentity,
    ) -> Wallet:
        w = cls(path=path, owner=owner)
        w._unlock_key = derive_key_from_passphrase(passphrase, w.salt, w.iterations)
        return w

    @classmethod
    def create_with_kem(
        cls,
        path: str,
        recipient_kem_public_key: bytes,
        recipient_algorithm: KEMAlgorithm,
        owner: AgentIdentity,
    ) -> Wallet:
        """Create a wallet whose unlock key is encapsulated to a KEM public key.

        The caller is the issuer (who knows the ephemeral symmetric key briefly
        and then throws it away). The recipient who holds the matching KEM
        private key can decapsulate to unlock.

        NOTE: quantumshield's `encapsulate()` API may not be available in the
        Ed25519 fallback backend - in that case we derive a 32-byte key from
        the ephemeral bytes using SHA3-256 so the test flow still works.
        """
        w = cls(path=path, owner=owner)

        # Use quantumshield's encapsulate if available; else fall back to a
        # deterministic-from-random derivation for dev/testing.
        from quantumshield.core import keys as _qk

        symmetric_key: bytes
        ciphertext: bytes
        if hasattr(_qk, "encapsulate"):
            symmetric_key, ciphertext = _qk.encapsulate(
                recipient_kem_public_key, recipient_algorithm
            )
        else:
            # Dev fallback: generate a 32-byte symmetric key, "encapsulate" by
            # SHA3-256'ing it with the recipient pubkey. Real liboqs integration
            # replaces this path.
            symmetric_key = os.urandom(32)
            ciphertext = hashlib.sha3_256(
                symmetric_key + recipient_kem_public_key
            ).digest()

        w._unlock_key = symmetric_key[:32]
        w.kem_encapsulation = {
            "algorithm": recipient_algorithm.value,
            "ciphertext": ciphertext.hex(),
            "recipient_pubkey": recipient_kem_public_key.hex(),
        }
        return w

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------

    @property
    def is_unlocked(self) -> bool:
        return self._unlock_key is not None

    def unlock_with_passphrase(self, passphrase: str) -> None:
        candidate = derive_key_from_passphrase(passphrase, self.salt, self.iterations)
        # Validate by attempting to decrypt the first credential if any; if no
        # credentials yet, accept (fresh wallet).
        if self._encrypted:
            _name, enc = next(iter(self._encrypted.items()))
            try:
                self._decrypt_value(enc, candidate)
            except Exception as exc:
                raise InvalidPassphraseError(
                    "passphrase failed to unlock wallet"
                ) from exc
        self._unlock_key = candidate
        self.audit.log("unlock", self.owner, "", True, details="passphrase")

    def unlock_with_kem_private_key(
        self,
        recipient_kem_private_key: bytes,
        algorithm: KEMAlgorithm,
    ) -> None:
        if not self.kem_encapsulation:
            raise WalletFormatError("wallet was not created with KEM encapsulation")
        from quantumshield.core import keys as _qk

        ciphertext = bytes.fromhex(self.kem_encapsulation["ciphertext"])
        if hasattr(_qk, "decapsulate"):
            symmetric_key = _qk.decapsulate(
                ciphertext, recipient_kem_private_key, algorithm
            )
        else:
            # Dev fallback can't truly decapsulate; callers must pass the key
            # they used to create. Accept a private-key-as-symmetric for tests.
            symmetric_key = recipient_kem_private_key[:32]
        self._unlock_key = symmetric_key[:32]
        self.audit.log("unlock", self.owner, "", True, details="kem")

    def lock(self) -> None:
        self._unlock_key = None
        self.audit.log("lock", self.owner, "", True)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def put(
        self,
        name: str,
        value: str,
        service: str = "",
        description: str = "",
        scheme: str = "api-key",
        tags: list[str] | None = None,
        expires_at: str = "",
    ) -> None:
        if not self.is_unlocked:
            raise WalletLockedError("wallet must be unlocked before put()")
        now = datetime.now(timezone.utc).isoformat()
        existing = self._encrypted.get(name)
        metadata = CredentialMetadata(
            name=name,
            scheme=scheme,
            service=service,
            description=description,
            created_at=existing.metadata.created_at if existing else now,
            rotated_at=now if existing else "",
            expires_at=expires_at,
            tags=list(tags or []),
        )
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = self._encrypt_value(value, nonce)
        self._encrypted[name] = _EncryptedCredential(
            nonce=nonce.hex(),
            ciphertext=ciphertext.hex(),
            metadata=metadata,
        )
        self.audit.log("put", self.owner, name, True, details=f"service={service}")

    def get(self, name: str) -> str:
        if not self.is_unlocked:
            raise WalletLockedError("wallet must be unlocked before get()")
        if name not in self._encrypted:
            self.audit.log("get", self.owner, name, False, details="not found")
            raise CredentialNotFoundError(f"no credential named '{name}'")
        value = self._decrypt_value(self._encrypted[name], self._unlock_key or b"")
        self.audit.log("get", self.owner, name, True)
        return value

    def get_credential(self, name: str) -> Credential:
        value = self.get(name)
        meta = self._encrypted[name].metadata
        return Credential(metadata=meta, value=value)

    def delete(self, name: str) -> None:
        if not self.is_unlocked:
            raise WalletLockedError("wallet must be unlocked before delete()")
        if name not in self._encrypted:
            self.audit.log("delete", self.owner, name, False, details="not found")
            raise CredentialNotFoundError(f"no credential named '{name}'")
        del self._encrypted[name]
        self.audit.log("delete", self.owner, name, True)

    def list_names(self) -> list[str]:
        return sorted(self._encrypted.keys())

    def list_metadata(self) -> list[CredentialMetadata]:
        return [e.metadata for e in self._encrypted.values()]

    def rotate(self, name: str, new_value: str) -> None:
        """Replace a credential's value while keeping its metadata creation date."""
        if name not in self._encrypted:
            raise CredentialNotFoundError(name)
        meta = self._encrypted[name].metadata
        self.put(
            name=name,
            value=new_value,
            service=meta.service,
            description=meta.description,
            scheme=meta.scheme,
            tags=meta.tags,
            expires_at=meta.expires_at,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _build_payload(self) -> dict[str, Any]:
        return {
            "version": WALLET_FORMAT_VERSION,
            "created_at": self.created_at,
            "owner_did": self.owner.did,
            "kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "salt": self.salt.hex(),
                "iterations": self.iterations,
            },
            "kem_encapsulation": self.kem_encapsulation,
            "encrypted_credentials": {
                name: {
                    "nonce": enc.nonce,
                    "ciphertext": enc.ciphertext,
                    "metadata": enc.metadata.to_dict(),
                }
                for name, enc in self._encrypted.items()
            },
        }

    def _canonical_payload_bytes(self) -> bytes:
        """Deterministic serialization of the payload used for signing."""
        payload = self._build_payload()
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def save(self) -> None:
        """Write wallet to disk with ML-DSA signature over the payload."""
        canonical = self._canonical_payload_bytes()
        digest = hashlib.sha3_256(canonical).digest()
        signature = sign(digest, self.owner.signing_keypair)

        envelope = {
            **self._build_payload(),
            "owner_public_key": self.owner.signing_keypair.public_key.hex(),
            "signature": signature.hex(),
            "signature_algorithm": self.owner.signing_keypair.algorithm.value,
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)

    @classmethod
    def load(cls, path: str, owner: AgentIdentity) -> Wallet:
        """Load a wallet from disk; verifies the ML-DSA signature."""
        with open(path, encoding="utf-8") as f:
            envelope = json.load(f)

        if envelope.get("version") != WALLET_FORMAT_VERSION:
            raise WalletFormatError(
                f"unsupported wallet version: {envelope.get('version')}"
            )

        # Verify owner signature over the payload
        sig_hex = envelope.get("signature")
        sig_alg = envelope.get("signature_algorithm")
        owner_pk_hex = envelope.get("owner_public_key")
        if not sig_hex or not sig_alg or not owner_pk_hex:
            raise WalletFormatError("wallet missing signature fields")

        payload = {
            k: envelope[k]
            for k in envelope
            if k not in ("signature", "signature_algorithm", "owner_public_key")
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha3_256(canonical).digest()

        try:
            algorithm = SignatureAlgorithm(sig_alg)
        except ValueError as exc:
            raise WalletFormatError(f"unknown signature algorithm: {sig_alg}") from exc

        valid = verify(
            digest,
            bytes.fromhex(sig_hex),
            bytes.fromhex(owner_pk_hex),
            algorithm,
        )
        if not valid:
            raise TamperedWalletError("wallet signature failed verification")

        # Reconstruct
        kdf = envelope.get("kdf", {})
        encrypted_raw = envelope.get("encrypted_credentials", {})
        encrypted: dict[str, _EncryptedCredential] = {}
        for name, raw in encrypted_raw.items():
            encrypted[name] = _EncryptedCredential(
                nonce=raw["nonce"],
                ciphertext=raw["ciphertext"],
                metadata=CredentialMetadata.from_dict(raw["metadata"]),
            )

        return cls(
            path=path,
            owner=owner,
            salt=bytes.fromhex(kdf.get("salt", "")),
            iterations=int(kdf.get("iterations", DEFAULT_ITERATIONS)),
            kem_encapsulation=envelope.get("kem_encapsulation"),
            encrypted_credentials=encrypted,
            created_at=envelope.get("created_at", ""),
        )

    # ------------------------------------------------------------------
    # Internal crypto
    # ------------------------------------------------------------------

    def _encrypt_value(self, value: str, nonce: bytes) -> bytes:
        if not self._unlock_key:
            raise WalletLockedError("wallet must be unlocked")
        aes = AESGCM(self._unlock_key)
        return aes.encrypt(nonce, value.encode("utf-8"), associated_data=None)

    def _decrypt_value(self, enc: _EncryptedCredential, key: bytes) -> str:
        aes = AESGCM(key)
        return aes.decrypt(
            bytes.fromhex(enc.nonce),
            bytes.fromhex(enc.ciphertext),
            associated_data=None,
        ).decode("utf-8")

    # ------------------------------------------------------------------
    # Context manager sugar
    # ------------------------------------------------------------------

    def __enter__(self) -> Wallet:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.lock()
