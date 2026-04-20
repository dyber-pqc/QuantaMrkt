"""LogReader - read sealed segments back, verify signatures + chain."""

from __future__ import annotations

import hashlib
import json
import os

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import verify

from pqc_audit_log_fs.errors import (
    SegmentCorruptedError,
    SegmentNotFoundError,
    SignatureVerificationError,
)
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.merkle import compute_merkle_root
from pqc_audit_log_fs.segment import AuditSegment, SegmentHeader


class LogReader:
    """Read-only access to a log directory."""

    def __init__(self, log_dir: str) -> None:
        if not os.path.isdir(log_dir):
            raise SegmentNotFoundError(f"no directory {log_dir}")
        self.log_dir = log_dir

    def list_segments(self) -> list[int]:
        nums: list[int] = []
        for name in os.listdir(self.log_dir):
            if name.startswith("segment-") and name.endswith(".sig.json"):
                try:
                    n = int(name[len("segment-"): len("segment-") + 5])
                    nums.append(n)
                except ValueError:
                    continue
        return sorted(nums)

    def read_header(self, segment_number: int) -> SegmentHeader:
        path = os.path.join(self.log_dir, f"segment-{segment_number:05d}.sig.json")
        if not os.path.exists(path):
            raise SegmentNotFoundError(f"no sig file for segment {segment_number}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return SegmentHeader.from_dict(data)

    def read_segment(self, segment_number: int) -> AuditSegment:
        header = self.read_header(segment_number)
        jsonl = os.path.join(self.log_dir, f"segment-{segment_number:05d}.log")
        if not os.path.exists(jsonl):
            raise SegmentNotFoundError(f"no jsonl file for segment {segment_number}")
        events: list[InferenceEvent] = []
        with open(jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(InferenceEvent.from_dict(json.loads(line)))
                except (json.JSONDecodeError, TypeError) as exc:
                    raise SegmentCorruptedError(
                        f"malformed jsonl in segment {segment_number}: {exc}"
                    ) from exc
        return AuditSegment(header=header, events=events)

    def verify_segment(self, segment_number: int) -> bool:
        """Verify (a) ML-DSA sig on header, (b) merkle_root matches recomputed root."""
        segment = self.read_segment(segment_number)
        header = segment.header
        leaves = [e.leaf_hash() for e in segment.events]
        recomputed = compute_merkle_root(leaves) if leaves else ""
        if recomputed != header.merkle_root:
            raise SegmentCorruptedError(
                f"segment {segment_number} merkle_root mismatch: "
                f"declared={header.merkle_root[:16]}..., "
                f"recomputed={recomputed[:16]}..."
            )
        try:
            algorithm = SignatureAlgorithm(header.algorithm)
        except ValueError as exc:
            raise SignatureVerificationError(
                f"unknown algorithm {header.algorithm}"
            ) from exc
        canonical = hashlib.sha3_256(header.canonical_bytes()).digest()
        if not verify(
            canonical,
            bytes.fromhex(header.signature),
            bytes.fromhex(header.public_key),
            algorithm,
        ):
            raise SignatureVerificationError(
                f"segment {segment_number} ML-DSA signature invalid"
            )
        return True

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify every segment's sig + chain link. Returns (ok, errors)."""
        errors: list[str] = []
        prev_root: str = ""
        for n in self.list_segments():
            try:
                self.verify_segment(n)
                header = self.read_header(n)
                if header.previous_segment_root != prev_root:
                    errors.append(
                        f"segment {n} chain break: expected prev "
                        f"{prev_root[:16]}..., got "
                        f"{header.previous_segment_root[:16]}..."
                    )
                prev_root = header.merkle_root
            except (SegmentCorruptedError, SignatureVerificationError) as exc:
                errors.append(f"segment {n}: {exc}")
                # Even if verification fails, try to track chain if header readable
                try:
                    header = self.read_header(n)
                    prev_root = header.merkle_root
                except SegmentNotFoundError:
                    pass
        return len(errors) == 0, errors
