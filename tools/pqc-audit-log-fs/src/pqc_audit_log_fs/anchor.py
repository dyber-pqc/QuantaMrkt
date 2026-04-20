"""MerkleAnchor - periodically publish segment roots to an external transparency log."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class AnchorSink(ABC):
    """Where anchored roots get published (blockchain, transparency log, etc.)."""

    @abstractmethod
    def publish(self, log_id: str, segment_number: int, merkle_root: str) -> str:
        """Return an opaque receipt/transaction ID."""


class NullAnchorSink(AnchorSink):
    """No-op sink - useful for tests."""

    def __init__(self) -> None:
        self.received: list[tuple[str, int, str]] = []

    def publish(self, log_id: str, segment_number: int, merkle_root: str) -> str:
        self.received.append((log_id, segment_number, merkle_root))
        return f"null-receipt-{segment_number}"


@dataclass
class MerkleAnchor:
    """Periodic anchoring of segment roots to an external store."""

    sink: AnchorSink
    published: dict[int, str] = field(default_factory=dict)

    def anchor_segment(
        self, log_id: str, segment_number: int, merkle_root: str
    ) -> str:
        receipt = self.sink.publish(log_id, segment_number, merkle_root)
        self.published[segment_number] = receipt
        return receipt
