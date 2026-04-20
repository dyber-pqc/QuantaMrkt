"""KeyRing - allow-list of trusted manufacturer public keys."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from pqc_bootloader.errors import UnknownKeyError


@dataclass
class KeyRingEntry:
    key_id: str  # fingerprint (hex SHA3-256 of public_key bytes)
    public_key: str  # hex
    algorithm: str
    manufacturer: str
    role: str = "firmware-signer"
    added_at: str = ""
    revoked: bool = False
    revocation_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class KeyRing:
    """Trust store of manufacturer public keys."""

    def __init__(self) -> None:
        self._entries: dict[str, KeyRingEntry] = {}

    @staticmethod
    def fingerprint(public_key_hex: str) -> str:
        return hashlib.sha3_256(bytes.fromhex(public_key_hex)).hexdigest()

    def add(
        self,
        public_key_hex: str,
        algorithm: str,
        manufacturer: str,
        role: str = "firmware-signer",
    ) -> KeyRingEntry:
        kid = self.fingerprint(public_key_hex)
        entry = KeyRingEntry(
            key_id=kid,
            public_key=public_key_hex,
            algorithm=algorithm,
            manufacturer=manufacturer,
            role=role,
            added_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entries[kid] = entry
        return entry

    def revoke(self, key_id: str, reason: str) -> None:
        if key_id not in self._entries:
            raise UnknownKeyError(f"no key with id {key_id}")
        self._entries[key_id].revoked = True
        self._entries[key_id].revocation_reason = reason

    def get(self, key_id: str) -> KeyRingEntry:
        if key_id not in self._entries:
            raise UnknownKeyError(f"no key with id {key_id}")
        return self._entries[key_id]

    def is_trusted(self, key_id: str) -> bool:
        return key_id in self._entries and not self._entries[key_id].revoked

    def list_entries(self) -> list[KeyRingEntry]:
        return list(self._entries.values())

    def export_json(self) -> str:
        return json.dumps(
            [e.to_dict() for e in self._entries.values()],
            indent=2,
        )

    def __len__(self) -> int:
        return len(self._entries)
