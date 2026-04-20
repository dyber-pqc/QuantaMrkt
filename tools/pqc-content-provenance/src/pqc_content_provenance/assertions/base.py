"""Assertion base class -- pluggable claims about content."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, ClassVar


@dataclass
class Assertion:
    """Base class for provenance assertions (C2PA-style claim facts)."""

    label: ClassVar[str] = "c2pa.generic"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["label"] = self.label
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Assertion:
        d = dict(data)
        d.pop("label", None)
        return cls(**d)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization used for hashing assertions."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def hash(self) -> str:
        return hashlib.sha3_256(self.canonical_bytes()).hexdigest()
