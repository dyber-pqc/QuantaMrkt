"""ContentManifest -- the core provenance record attached to every output."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from pqc_content_provenance.assertions import ASSERTION_REGISTRY, Assertion
from pqc_content_provenance.errors import InvalidManifestError, UnknownAssertionError


@dataclass
class ModelAttribution:
    """Identifies the model that produced the content."""

    model_did: str                             # did:pqaid:...
    model_name: str                            # e.g. "Llama-3-8B-Instruct"
    model_version: str                         # e.g. "1.0"
    registry_url: str = ""                     # e.g. https://quantamrkt.com/models/...
    model_manifest_hash: str = ""              # hash of the model manifest in Shield Registry

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GenerationContext:
    """What produced the content -- prompt hash, parameters, etc."""

    prompt_hash: str = ""                      # SHA3-256 of the prompt
    input_content_hashes: list[str] = field(default_factory=list)  # hashes of reference inputs
    parameters: dict = field(default_factory=dict)
    generated_at: str = ""                     # ISO-8601

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ContentManifest:
    """The signed provenance manifest attached to AI-generated content.

    Stores: manifest ID, content hash, model attribution, generation context,
    assertions (pluggable claims), signature chain (see ProvenanceChain).
    """

    manifest_id: str
    content_hash: str                          # SHA3-256 of the output bytes
    content_type: str                          # mime-type (text/plain, image/png, ...)
    content_size: int                          # bytes
    model_attribution: ModelAttribution
    generation_context: GenerationContext
    assertions: list[Assertion] = field(default_factory=list)
    created_at: str = ""
    previous_manifest_id: str | None = None    # prior link in chain (re-signing, editing)

    # Filled in by ManifestSigner
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""                        # hex
    public_key: str = ""                       # hex
    signed_at: str = ""

    @staticmethod
    def compute_content_hash(content: bytes) -> str:
        return hashlib.sha3_256(content).hexdigest()

    @classmethod
    def create(
        cls,
        content: bytes,
        content_type: str,
        model_attribution: ModelAttribution,
        generation_context: GenerationContext,
        assertions: list[Assertion] | None = None,
        previous_manifest_id: str | None = None,
    ) -> ContentManifest:
        return cls(
            manifest_id=f"urn:pqc-prov:{uuid.uuid4().hex}",
            content_hash=cls.compute_content_hash(content),
            content_type=content_type,
            content_size=len(content),
            model_attribution=model_attribution,
            generation_context=generation_context,
            assertions=list(assertions or []),
            created_at=datetime.now(timezone.utc).isoformat(),
            previous_manifest_id=previous_manifest_id,
        )

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes used for signing (excludes the signature itself)."""
        payload = {
            "manifest_id": self.manifest_id,
            "content_hash": self.content_hash,
            "content_type": self.content_type,
            "content_size": self.content_size,
            "model_attribution": self.model_attribution.to_dict(),
            "generation_context": self.generation_context.to_dict(),
            "assertions": [a.to_dict() for a in self.assertions],
            "created_at": self.created_at,
            "previous_manifest_id": self.previous_manifest_id,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["model_attribution"] = self.model_attribution.to_dict()
        d["generation_context"] = self.generation_context.to_dict()
        d["assertions"] = [a.to_dict() for a in self.assertions]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContentManifest:
        try:
            assertions_raw = data.get("assertions", [])
            assertions: list[Assertion] = []
            for a in assertions_raw:
                label = a.get("label")
                cls_ = ASSERTION_REGISTRY.get(label or "")
                if not cls_:
                    raise UnknownAssertionError(f"Unknown assertion label: {label}")
                assertion = cls_.from_dict(a)
                assertions.append(assertion)

            mattr = data["model_attribution"]
            gctx = data["generation_context"]
            return cls(
                manifest_id=data["manifest_id"],
                content_hash=data["content_hash"],
                content_type=data["content_type"],
                content_size=data["content_size"],
                model_attribution=ModelAttribution(**mattr),
                generation_context=GenerationContext(**gctx),
                assertions=assertions,
                created_at=data.get("created_at", ""),
                previous_manifest_id=data.get("previous_manifest_id"),
                signer_did=data.get("signer_did", ""),
                algorithm=data.get("algorithm", ""),
                signature=data.get("signature", ""),
                public_key=data.get("public_key", ""),
                signed_at=data.get("signed_at", ""),
            )
        except KeyError as e:
            raise InvalidManifestError(f"Missing required field: {e}") from e

    @classmethod
    def from_json(cls, blob: str) -> ContentManifest:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as e:
            raise InvalidManifestError(f"Invalid JSON: {e}") from e
        return cls.from_dict(data)
