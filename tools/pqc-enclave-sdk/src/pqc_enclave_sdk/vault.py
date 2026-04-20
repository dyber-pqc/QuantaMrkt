"""EnclaveVault - high-level API over an EnclaveBackend."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from quantumshield.core.algorithms import KEMAlgorithm
from quantumshield.core.keys import generate_kem_keypair

from pqc_enclave_sdk.artifact import (
    ArtifactKind,
    ArtifactMetadata,
    EnclaveArtifact,
    EncryptedArtifact,
)
from pqc_enclave_sdk.audit import EnclaveAuditLog
from pqc_enclave_sdk.backends.base import EnclaveBackend
from pqc_enclave_sdk.errors import (
    DecryptionError,
    EnclaveLockedError,
    UnknownArtifactError,
)

NONCE_SIZE = 12
DEFAULT_SESSION_TTL = 3600


def establish_enclave_session(
    backend: EnclaveBackend,
    algorithm: KEMAlgorithm = KEMAlgorithm.ML_KEM_768,
    ttl_seconds: int = DEFAULT_SESSION_TTL,
) -> tuple[bytes, str, str]:
    """Derive a 32-byte AES key from a fresh ML-KEM-768 keypair bound to the device.

    In production: the enclave runs Decapsulate on a ciphertext encrypted to
    the enclave's KEM public key. Here we generate the KEM keypair in-process
    and derive the symmetric key deterministically so tests work with the
    Ed25519/stub backend.

    Returns: (symmetric_key, key_id, expires_at_iso)
    """
    kp = generate_kem_keypair(algorithm)
    symmetric = hashlib.sha3_256(kp.private_key + kp.public_key).digest()
    key_id = f"urn:pqc-enclave-key:{uuid.uuid4().hex}"
    exp = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    backend.store_session_key(key_id, symmetric, exp)
    return symmetric, key_id, exp


@dataclass
class EnclaveVault:
    """High-level vault backed by an EnclaveBackend + AES-256-GCM per artifact.

    Usage:
        backend = InMemoryEnclaveBackend(device_id="iphone-alice")
        vault = EnclaveVault(backend)
        vault.unlock()
        vault.put_artifact(
            name="llama-3.2-1b-int4",
            kind=ArtifactKind.MODEL_WEIGHTS,
            content=weights_bytes,
        )
        vault.save()
        # later...
        vault.unlock()
        weights = vault.get_artifact("llama-3.2-1b-int4").content
    """

    backend: EnclaveBackend
    audit: EnclaveAuditLog = field(default_factory=EnclaveAuditLog)
    _symmetric_key: bytes | None = None
    _key_id: str = ""
    _expires_at: str = ""
    _store: dict[str, EncryptedArtifact] = field(default_factory=dict)

    @property
    def is_unlocked(self) -> bool:
        if self._symmetric_key is None:
            return False
        try:
            exp = datetime.fromisoformat(self._expires_at)
            return datetime.now(timezone.utc) <= exp
        except ValueError:
            return False

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise EnclaveLockedError("enclave vault is locked; call unlock() first")

    # -- lifecycle ---------------------------------------------------------

    def unlock(self, ttl_seconds: int = DEFAULT_SESSION_TTL) -> None:
        key, key_id, exp = establish_enclave_session(
            self.backend, ttl_seconds=ttl_seconds
        )
        self._symmetric_key = key
        self._key_id = key_id
        self._expires_at = exp
        self._store = dict(self.backend.load_artifacts())
        self.audit.log_unlock(self.backend.device_id, key_id)

    def lock(self) -> None:
        self._symmetric_key = None
        self._key_id = ""
        self._expires_at = ""
        self.audit.log_lock(self.backend.device_id)

    def save(self) -> None:
        """Persist the encrypted store to the backend."""
        self.backend.save_artifacts(dict(self._store))

    # -- AAD ---------------------------------------------------------------

    @staticmethod
    def _aad(metadata: ArtifactMetadata, content_hash: str, key_id: str) -> bytes:
        payload = {
            "metadata": metadata.to_dict(),
            "content_hash": content_hash,
            "key_id": key_id,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    # -- CRUD --------------------------------------------------------------

    def put_artifact(
        self,
        name: str,
        kind: ArtifactKind,
        content: bytes,
        version: str = "",
        app_bundle_id: str = "",
        model_did: str = "",
        tags: tuple[str, ...] = (),
        description: str = "",
    ) -> EncryptedArtifact:
        self._require_unlocked()
        assert self._symmetric_key is not None
        artifact_id = f"urn:pqc-enclave-art:{uuid.uuid4().hex}"
        metadata = ArtifactMetadata(
            artifact_id=artifact_id,
            name=name,
            kind=kind,
            version=version,
            app_bundle_id=app_bundle_id,
            size_bytes=len(content),
            created_at=datetime.now(timezone.utc).isoformat(),
            device_id=self.backend.device_id,
            model_did=model_did,
            tags=tuple(tags),
            description=description,
        )
        content_hash = EnclaveArtifact.content_hash(content)
        nonce = os.urandom(NONCE_SIZE)
        aes = AESGCM(self._symmetric_key)
        ct = aes.encrypt(
            nonce, content, self._aad(metadata, content_hash, self._key_id)
        )
        enc = EncryptedArtifact(
            metadata=metadata,
            nonce=nonce.hex(),
            ciphertext=ct.hex(),
            content_hash=content_hash,
            key_id=self._key_id,
        )
        self._store[artifact_id] = enc
        self._store[f"name:{name}"] = enc
        self.audit.log_put(self.backend.device_id, artifact_id, name, kind.value)
        return enc

    def get_artifact(self, name_or_id: str) -> EnclaveArtifact:
        self._require_unlocked()
        assert self._symmetric_key is not None
        key = name_or_id
        if key not in self._store:
            key = f"name:{name_or_id}"
        if key not in self._store:
            self.audit.log_get(
                self.backend.device_id, name_or_id, success=False, details="not found"
            )
            raise UnknownArtifactError(f"no artifact '{name_or_id}'")
        enc = self._store[key]
        aes = AESGCM(self._symmetric_key)
        aad = self._aad(enc.metadata, enc.content_hash, enc.key_id)
        try:
            content = aes.decrypt(
                bytes.fromhex(enc.nonce), bytes.fromhex(enc.ciphertext), aad
            )
        except Exception as exc:
            raise DecryptionError(f"AES-GCM decrypt failed: {exc}") from exc
        self.audit.log_get(
            self.backend.device_id, enc.metadata.artifact_id, success=True
        )
        return EnclaveArtifact(metadata=enc.metadata, content=content)

    def delete_artifact(self, name_or_id: str) -> None:
        self._require_unlocked()
        key = name_or_id
        if key not in self._store:
            key = f"name:{name_or_id}"
        if key not in self._store:
            raise UnknownArtifactError(f"no artifact '{name_or_id}'")
        enc = self._store.pop(key)
        for k in (enc.metadata.artifact_id, f"name:{enc.metadata.name}"):
            self._store.pop(k, None)
        self.audit.log_delete(
            self.backend.device_id, enc.metadata.artifact_id, enc.metadata.name
        )

    def list_artifacts(self) -> list[ArtifactMetadata]:
        self._require_unlocked()
        seen: dict[str, ArtifactMetadata] = {}
        for _k, enc in self._store.items():
            seen[enc.metadata.artifact_id] = enc.metadata
        return list(seen.values())

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> EnclaveVault:
        if not self.is_unlocked:
            self.unlock()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.lock()
