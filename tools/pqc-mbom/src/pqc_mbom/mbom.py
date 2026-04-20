"""MBOM - the signed bill of materials for an AI model."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pqc_mbom.component import ModelComponent, ComponentType
from pqc_mbom.errors import InvalidMBOMError, MissingComponentError


SCHEMA_VERSION = "1.0"


@dataclass
class MBOM:
    """A Model Bill of Materials.

    Contains the model's own identity (name, version, supplier) and an
    enumeration of ModelComponents with hashes. The MBOM as a whole is
    signed separately via MBOMSigner.
    """
    mbom_id: str
    schema_version: str
    model_name: str
    model_version: str
    supplier: str = ""
    description: str = ""
    components: list[ModelComponent] = field(default_factory=list)
    created_at: str = ""
    components_root_hash: str = ""              # SHA3-256 over sorted component hashes

    # Set by MBOMSigner.sign
    signer_did: str = ""
    algorithm: str = ""
    signature: str = ""
    public_key: str = ""
    signed_at: str = ""

    @classmethod
    def create(
        cls,
        model_name: str,
        model_version: str,
        supplier: str = "",
        description: str = "",
        components: list[ModelComponent] | None = None,
    ) -> MBOM:
        m = cls(
            mbom_id=f"urn:pqc-mbom:{uuid.uuid4().hex}",
            schema_version=SCHEMA_VERSION,
            model_name=model_name,
            model_version=model_version,
            supplier=supplier,
            description=description,
            components=list(components or []),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        m.recompute_root()
        return m

    def recompute_root(self) -> str:
        component_hashes = sorted(c.hash() for c in self.components)
        concat = "|".join(component_hashes).encode("utf-8")
        self.components_root_hash = hashlib.sha3_256(concat).hexdigest()
        return self.components_root_hash

    def get_component(self, component_id: str) -> ModelComponent:
        for c in self.components:
            if c.component_id == component_id:
                return c
        raise MissingComponentError(f"no component with id '{component_id}'")

    def components_by_type(self, ctype: ComponentType) -> list[ModelComponent]:
        return [c for c in self.components if c.component_type == ctype]

    def canonical_bytes(self) -> bytes:
        payload = {
            "mbom_id": self.mbom_id,
            "schema_version": self.schema_version,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "supplier": self.supplier,
            "description": self.description,
            "components": [c.to_dict() for c in self.components],
            "created_at": self.created_at,
            "components_root_hash": self.components_root_hash,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mbom_id": self.mbom_id,
            "schema_version": self.schema_version,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "supplier": self.supplier,
            "description": self.description,
            "components": [c.to_dict() for c in self.components],
            "created_at": self.created_at,
            "components_root_hash": self.components_root_hash,
            "signer_did": self.signer_did,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key": self.public_key,
            "signed_at": self.signed_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MBOM:
        try:
            return cls(
                mbom_id=data["mbom_id"],
                schema_version=data.get("schema_version", SCHEMA_VERSION),
                model_name=data["model_name"],
                model_version=data["model_version"],
                supplier=data.get("supplier", ""),
                description=data.get("description", ""),
                components=[ModelComponent.from_dict(c) for c in data.get("components", [])],
                created_at=data.get("created_at", ""),
                components_root_hash=data.get("components_root_hash", ""),
                signer_did=data.get("signer_did", ""),
                algorithm=data.get("algorithm", ""),
                signature=data.get("signature", ""),
                public_key=data.get("public_key", ""),
                signed_at=data.get("signed_at", ""),
            )
        except KeyError as e:
            raise InvalidMBOMError(f"missing required field: {e}") from e

    @classmethod
    def from_json(cls, blob: str) -> MBOM:
        try:
            return cls.from_dict(json.loads(blob))
        except json.JSONDecodeError as e:
            raise InvalidMBOMError(f"invalid JSON: {e}") from e


class MBOMBuilder:
    """Fluent builder for MBOMs.

    Usage:
        builder = MBOMBuilder("Llama-3-8B-Instruct", "1.0", supplier="Meta")
        builder.add_base_architecture("Llama-3", version="3.0", content_hash=...)
        builder.add_training_data("common-crawl-2024", content_hash=..., size=1_000_000_000_000)
        builder.add_fine_tuning_data("instruct-v1", content_hash=...)
        builder.add_rlhf_data("hh-rlhf", content_hash=...)
        builder.add_tokenizer("Llama-3-tokenizer", content_hash=...)
        builder.add_weights("model.safetensors", content_hash=..., size=16_000_000_000)
        mbom = builder.build()
    """

    def __init__(self, model_name: str, model_version: str, supplier: str = ""):
        self.model_name = model_name
        self.model_version = model_version
        self.supplier = supplier
        self.description = ""
        self.components: list[ModelComponent] = []

    def _component_id(self, name: str) -> str:
        return f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"

    def add_component(self, component: ModelComponent) -> MBOMBuilder:
        self.components.append(component)
        return self

    def add_base_architecture(
        self, name: str, version: str = "", content_hash: str = "", **kwargs: Any
    ) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.BASE_ARCHITECTURE,
            name=name, version=version, content_hash=content_hash, **kwargs,
        ))

    def add_weights(
        self, name: str, content_hash: str = "", content_size: int = 0, **kwargs: Any
    ) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.WEIGHTS,
            name=name, content_hash=content_hash, content_size=content_size, **kwargs,
        ))

    def add_training_data(
        self, name: str, content_hash: str = "", content_size: int = 0, **kwargs: Any
    ) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.TRAINING_DATA,
            name=name, content_hash=content_hash, content_size=content_size, **kwargs,
        ))

    def add_fine_tuning_data(
        self, name: str, content_hash: str = "", **kwargs: Any
    ) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.FINE_TUNING_DATA,
            name=name, content_hash=content_hash, **kwargs,
        ))

    def add_rlhf_data(self, name: str, content_hash: str = "", **kwargs: Any) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.RLHF_DATA,
            name=name, content_hash=content_hash, **kwargs,
        ))

    def add_tokenizer(self, name: str, content_hash: str = "", **kwargs: Any) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.TOKENIZER,
            name=name, content_hash=content_hash, **kwargs,
        ))

    def add_quantization(self, name: str, **kwargs: Any) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.QUANTIZATION_METHOD,
            name=name, **kwargs,
        ))

    def add_evaluation(self, name: str, content_hash: str = "", **kwargs: Any) -> MBOMBuilder:
        return self.add_component(ModelComponent(
            component_id=self._component_id(name),
            component_type=ComponentType.EVALUATION_BENCHMARK,
            name=name, content_hash=content_hash, **kwargs,
        ))

    def set_description(self, description: str) -> MBOMBuilder:
        self.description = description
        return self

    def build(self) -> MBOM:
        return MBOM.create(
            model_name=self.model_name,
            model_version=self.model_version,
            supplier=self.supplier,
            description=self.description,
            components=list(self.components),
        )
