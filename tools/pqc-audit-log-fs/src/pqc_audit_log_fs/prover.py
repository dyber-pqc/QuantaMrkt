"""InclusionProver - generate and verify proofs that an event is in a segment."""

from __future__ import annotations

from pqc_audit_log_fs.errors import SegmentNotFoundError
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.merkle import (
    InclusionProof,
    build_merkle_proof,
    verify_inclusion,
)
from pqc_audit_log_fs.reader import LogReader


class InclusionProver:
    """Produce inclusion proofs for events stored in a log."""

    def __init__(self, reader: LogReader) -> None:
        self.reader = reader

    def prove_event(
        self, segment_number: int, event_id: str
    ) -> InclusionProof:
        segment = self.reader.read_segment(segment_number)
        idx: int | None = None
        for i, e in enumerate(segment.events):
            if e.event_id == event_id:
                idx = i
                break
        if idx is None:
            raise SegmentNotFoundError(
                f"event {event_id} not in segment {segment_number}"
            )
        leaves = [e.leaf_hash() for e in segment.events]
        return build_merkle_proof(leaves, idx, segment.header.merkle_root)

    @staticmethod
    def verify_proof(event: InferenceEvent, proof: InclusionProof) -> bool:
        if event.leaf_hash() != proof.leaf_hash:
            return False
        return verify_inclusion(proof)
