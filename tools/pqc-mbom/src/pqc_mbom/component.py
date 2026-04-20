"""AI model component types and data structures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class ComponentType(str, Enum):
    """Categories of AI model components tracked by an MBOM."""
    BASE_ARCHITECTURE = "base-architecture"     # e.g. Llama-3 8B architecture
    WEIGHTS = "weights"                         # serialized weights file
    TRAINING_DATA = "training-data"             # raw training dataset
    FINE_TUNING_DATA = "fine-tuning-data"
    RLHF_DATA = "rlhf-data"                     # human feedback dataset
    EVALUATION_BENCHMARK = "evaluation-benchmark"
    TOKENIZER = "tokenizer"
    QUANTIZATION_METHOD = "quantization-method"
    CODE = "code"                               # training/inference code
    CONFIG = "config"                           # config files (JSON/YAML)
    ADAPTER = "adapter"                         # LoRA/QLoRA adapter weights
    SAFETY_MODEL = "safety-model"               # content filter / classifier
    OTHER = "other"


@dataclass(frozen=True)
class LicenseInfo:
    """License declaration for a component."""
    spdx_id: str = ""                           # e.g. "apache-2.0", "cc-by-4.0"
    name: str = ""                              # human-readable name
    url: str = ""                               # link to license text
    commercial_use: bool = False
    attribution_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComponentReference:
    """A reference/link from one component to another (dependency)."""
    component_id: str
    relationship: str                           # "depends-on" | "derived-from" | "contains"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelComponent:
    """One entry in the MBOM.

    content_hash is SHA3-256 over the bytes the component represents (weights,
    data files, code, etc.). For pointer-only components (e.g. a published
    dataset referenced by URL), you can supply content_hash of the declared
    manifest and set external_url.
    """
    component_id: str                           # stable UUID or slug
    component_type: ComponentType
    name: str
    version: str = ""
    content_hash: str = ""                      # hex SHA3-256
    content_size: int = 0                       # bytes; 0 = unknown
    supplier: str = ""                          # organization
    author: str = ""                            # person
    external_url: str = ""                      # where to fetch (optional)
    license: LicenseInfo = field(default_factory=LicenseInfo)
    references: list[ComponentReference] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)   # arbitrary extras

    @staticmethod
    def hash_content(content: bytes) -> str:
        return hashlib.sha3_256(content).hexdigest()

    def canonical_bytes(self) -> bytes:
        payload = {
            "component_id": self.component_id,
            "component_type": self.component_type.value,
            "name": self.name,
            "version": self.version,
            "content_hash": self.content_hash,
            "content_size": self.content_size,
            "supplier": self.supplier,
            "author": self.author,
            "external_url": self.external_url,
            "license": self.license.to_dict(),
            "references": [r.to_dict() for r in self.references],
            "properties": self.properties,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def hash(self) -> str:
        return hashlib.sha3_256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type.value,
            "name": self.name,
            "version": self.version,
            "content_hash": self.content_hash,
            "content_size": self.content_size,
            "supplier": self.supplier,
            "author": self.author,
            "external_url": self.external_url,
            "license": self.license.to_dict(),
            "references": [r.to_dict() for r in self.references],
            "properties": dict(self.properties),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelComponent:
        lic = data.get("license", {})
        return cls(
            component_id=data["component_id"],
            component_type=ComponentType(data["component_type"]),
            name=data["name"],
            version=data.get("version", ""),
            content_hash=data.get("content_hash", ""),
            content_size=int(data.get("content_size", 0)),
            supplier=data.get("supplier", ""),
            author=data.get("author", ""),
            external_url=data.get("external_url", ""),
            license=LicenseInfo(
                spdx_id=lic.get("spdx_id", ""),
                name=lic.get("name", ""),
                url=lic.get("url", ""),
                commercial_use=bool(lic.get("commercial_use", False)),
                attribution_required=bool(lic.get("attribution_required", True)),
            ),
            references=[ComponentReference(**r) for r in data.get("references", [])],
            properties=dict(data.get("properties", {})),
        )
