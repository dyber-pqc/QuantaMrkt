"""Action credentials for post-quantum agent identity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from quantumshield.core.algorithms import SignatureAlgorithm


@dataclass
class ActionCredential:
    """A signed credential attesting that an agent performed an action."""

    signer_did: str
    action: str
    target: str
    signed_at: datetime
    signature: bytes
    algorithm: SignatureAlgorithm
