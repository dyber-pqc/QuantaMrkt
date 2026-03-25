"""Model manifest creation, signing, and verification."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from quantumshield.core.keys import SigningKeypair
from quantumshield.core.signatures import sign, verify


class ModelMetadata(BaseModel):
    """Metadata about a model."""

    name: str = "unknown"
    version: str = "0.0.0"
    framework: str = "unknown"
    architecture: str = ""
    description: str = ""
    author: str = ""
    license: str = ""


class FileEntry(BaseModel):
    """A file entry in the model manifest with its cryptographic hash."""

    path: str
    size: int
    hash_algorithm: str = "sha3-256"
    hash_value: str


class SignatureEntry(BaseModel):
    """A signature over the manifest by an agent or authority."""

    signer: str
    algorithm: str
    signature: str  # hex-encoded
    signed_at: str
    attestation_type: str = "origin"


class ModelManifest(BaseModel):
    """A cryptographically signed manifest for a model artifact.

    The manifest records all files in a model directory along with their
    SHA3-256 hashes, provenance metadata, and one or more post-quantum
    digital signatures.
    """

    manifest_version: str = "1.0.0"
    model: ModelMetadata = Field(default_factory=ModelMetadata)
    files: list[FileEntry] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    signatures: list[SignatureEntry] = Field(default_factory=list)
    hndl_assessment: Optional[dict] = None

    @classmethod
    def from_model(
        cls,
        path: str,
        metadata: ModelMetadata | None = None,
        hash_algorithm: str = "sha3-256",
    ) -> ModelManifest:
        """Create a manifest by walking a model directory and hashing all files.

        Args:
            path: Path to the model directory.
            metadata: Optional model metadata. Defaults to unknown.
            hash_algorithm: Hash algorithm to use. Defaults to SHA3-256.

        Returns:
            A new ModelManifest with file entries for every file in the directory.
        """
        model_path = Path(path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model path does not exist: {path}")

        files: list[FileEntry] = []

        if model_path.is_file():
            # Single file
            file_hash = _hash_file(str(model_path), hash_algorithm)
            files.append(FileEntry(
                path=model_path.name,
                size=model_path.stat().st_size,
                hash_algorithm=hash_algorithm,
                hash_value=file_hash,
            ))
        else:
            # Directory: walk all files
            for root, _dirs, filenames in os.walk(model_path):
                for filename in sorted(filenames):
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, model_path)
                    file_hash = _hash_file(file_path, hash_algorithm)
                    file_size = os.path.getsize(file_path)
                    files.append(FileEntry(
                        path=rel_path.replace("\\", "/"),
                        size=file_size,
                        hash_algorithm=hash_algorithm,
                        hash_value=file_hash,
                    ))

        return cls(
            model=metadata or ModelMetadata(),
            files=files,
            provenance={
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tool": "quantumshield",
                "tool_version": "0.1.0",
            },
        )

    def sign(self, keypair: SigningKeypair, signer_did: str = "", attestation_type: str = "origin") -> None:
        """Sign the manifest with a post-quantum keypair.

        Appends a new signature entry to the manifest's signature list.

        Args:
            keypair: The signing keypair to use.
            signer_did: The DID of the signer.
            attestation_type: The type of attestation (e.g., "origin", "review", "audit").
        """
        # Create canonical representation for signing (exclude existing signatures)
        canonical = self._canonical_bytes()
        signature = sign(canonical, keypair)

        entry = SignatureEntry(
            signer=signer_did or f"key:{keypair.public_key.hex()[:16]}",
            algorithm=keypair.algorithm.value,
            signature=signature.hex(),
            signed_at=datetime.now(timezone.utc).isoformat(),
            attestation_type=attestation_type,
        )
        self.signatures.append(entry)

    def verify(self) -> bool:
        """Verify all signatures on the manifest.

        Returns:
            True if all signatures are valid, False otherwise.

        .. note::
            Currently uses stub verification. TODO: Implement full PQ signature verification.
        """
        if not self.signatures:
            return False

        canonical = self._canonical_bytes()
        for sig_entry in self.signatures:
            signature = bytes.fromhex(sig_entry.signature)
            # TODO: Look up signer's public key from DID or key reference
            # For now, use stub verification
            from quantumshield.core.algorithms import SignatureAlgorithm
            if not verify(canonical, signature, b"", SignatureAlgorithm(sig_entry.algorithm)):
                return False

        return True

    def save(self, path: str) -> None:
        """Save the manifest to a JSON file.

        Args:
            path: Output file path.
        """
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))

    def _canonical_bytes(self) -> bytes:
        """Create a canonical byte representation for signing.

        Excludes signatures field to allow multiple independent signatures.
        """
        data = self.model_dump(exclude={"signatures"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return canonical.encode("utf-8")


def _hash_file(path: str, algorithm: str = "sha3-256") -> str:
    """Hash a file using the specified algorithm.

    Args:
        path: Path to the file to hash.
        algorithm: Hash algorithm name. Supports sha3-256 and sha3-512.

    Returns:
        Hex-encoded hash string.
    """
    if algorithm == "sha3-256":
        hasher = hashlib.sha3_256()
    elif algorithm == "sha3-512":
        hasher = hashlib.sha3_512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()
