"""KeyRotationPolicy - decides when to rotate a TenantSession's key."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from pqc_kv_cache.session import TenantSession


class RotationTrigger(str, Enum):
    ENTRY_COUNT = "entry-count"
    TIME_ELAPSED = "time-elapsed"
    MANUAL = "manual"


@dataclass
class KeyRotationPolicy:
    """Rotate session keys after N entries or T seconds, whichever comes first."""

    max_entries: int = 100_000
    max_age_seconds: int = 300

    def should_rotate(
        self, session: TenantSession
    ) -> tuple[bool, RotationTrigger | None]:
        if session.entries_encrypted >= self.max_entries:
            return True, RotationTrigger.ENTRY_COUNT
        try:
            created = datetime.fromisoformat(session.created_at)
            age = (datetime.now(timezone.utc) - created).total_seconds()
            if age >= self.max_age_seconds:
                return True, RotationTrigger.TIME_ELAPSED
        except ValueError:
            pass
        return False, None

    def rotate(self, session: TenantSession) -> bytes:
        """Rotate the session key in place. Returns the new key (opaque 32 bytes)."""
        new_key = os.urandom(32)
        session.rotate_key(new_key)
        return new_key
