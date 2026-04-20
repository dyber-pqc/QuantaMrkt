"""ChannelSession - encrypted CPU<->GPU channel using ML-KEM-derived AES-256-GCM key."""

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

from pqc_gpu_driver.errors import (
    ChannelExpiredError,
    DecryptionError,
    NonceReplayError,
)
from pqc_gpu_driver.tensor import EncryptedTensor, TensorMetadata

NONCE_SIZE = 12
SESSION_TTL_SECONDS = 3600


def establish_channel(
    cpu_side_label: str = "cpu",
    gpu_side_label: str = "gpu",
    algorithm: KEMAlgorithm = KEMAlgorithm.ML_KEM_768,
    ttl_seconds: int = SESSION_TTL_SECONDS,
) -> tuple[ChannelSession, ChannelSession]:
    """Produce two matching ChannelSessions sharing the same symmetric key.

    In production the CPU side runs ML-KEM encapsulation to the GPU's public
    key. Here we derive a symmetric key from a fresh ML-KEM keypair so tests
    work without liboqs. The two sides can encrypt/decrypt each other.
    """
    kp = generate_kem_keypair(algorithm)
    # Derive 32-byte symmetric key from the KEM keypair deterministically.
    # In a real deployment, this is the output of ML-KEM.Decapsulate on both sides.
    shared = hashlib.sha3_256(kp.private_key + kp.public_key).digest()

    session_id = f"urn:pqc-gpu-sess:{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)

    cpu_session = ChannelSession(
        session_id=session_id,
        peer_label=gpu_side_label,
        symmetric_key=shared,
        algorithm=algorithm.value,
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
    )
    gpu_session = ChannelSession(
        session_id=session_id,
        peer_label=cpu_side_label,
        symmetric_key=shared,
        algorithm=algorithm.value,
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
    )
    return cpu_session, gpu_session


@dataclass
class ChannelSession:
    """One side of an encrypted CPU<->GPU channel.

    Encryption:
      - AES-256-GCM per tensor transfer
      - Nonce = 12 bytes random (unique per message); stored with ciphertext
      - AAD = canonical bytes of TensorMetadata + sequence_number
        (binds metadata + ordering)
      - Sequence number enforced monotonically on recv side (replay protection)
    """

    session_id: str
    peer_label: str
    symmetric_key: bytes
    algorithm: str
    created_at: str
    expires_at: str
    next_send_seq: int = 1
    last_recv_seq: int = 0
    _used_nonces_recent: list[str] = field(default_factory=list)

    def is_valid(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now(timezone.utc) <= exp
        except ValueError:
            return False

    def _check_valid(self) -> None:
        if not self.is_valid():
            raise ChannelExpiredError(f"session {self.session_id} is expired")

    @staticmethod
    def _aad(metadata: TensorMetadata, sequence_number: int) -> bytes:
        payload = {
            "metadata": metadata.to_dict(),
            "sequence_number": sequence_number,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def encrypt_tensor(
        self, tensor_bytes: bytes, metadata: TensorMetadata
    ) -> EncryptedTensor:
        """Encrypt tensor bytes for transmission across PCIe."""
        self._check_valid()
        nonce = os.urandom(NONCE_SIZE)
        seq = self.next_send_seq
        self.next_send_seq += 1
        aes = AESGCM(self.symmetric_key)
        aad = self._aad(metadata, seq)
        ct = aes.encrypt(nonce, tensor_bytes, aad)
        return EncryptedTensor(
            metadata=metadata,
            nonce=nonce.hex(),
            ciphertext=ct.hex(),
            sequence_number=seq,
        )

    def decrypt_tensor(self, enc: EncryptedTensor) -> bytes:
        """Decrypt a tensor received over the channel.

        Enforces strict monotonicity of sequence numbers to prevent replay.
        """
        self._check_valid()
        if enc.sequence_number <= self.last_recv_seq:
            raise NonceReplayError(
                f"sequence {enc.sequence_number} <= last_recv {self.last_recv_seq}"
            )
        if enc.nonce in self._used_nonces_recent:
            raise NonceReplayError(f"nonce {enc.nonce} already seen")

        aes = AESGCM(self.symmetric_key)
        aad = self._aad(enc.metadata, enc.sequence_number)
        try:
            pt = aes.decrypt(
                bytes.fromhex(enc.nonce), bytes.fromhex(enc.ciphertext), aad
            )
        except Exception as exc:
            raise DecryptionError(f"AES-GCM decrypt failed: {exc}") from exc

        self.last_recv_seq = enc.sequence_number
        self._used_nonces_recent.append(enc.nonce)
        if len(self._used_nonces_recent) > 1024:
            self._used_nonces_recent = self._used_nonces_recent[-1024:]
        return pt
