"""LogAppender - append-only writer producing rotating AuditSegments on disk."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from types import TracebackType

from quantumshield.core.signatures import sign
from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs.errors import AppendToSealedSegmentError
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.segment import AuditSegment, SegmentHeader


@dataclass
class RotationPolicy:
    """Rotate when the current segment hits either threshold."""

    max_events_per_segment: int = 10_000
    max_bytes_per_segment: int = 10 * 1024 * 1024    # 10 MB default
    max_segment_age_seconds: int = 3600              # 1 hour

    def should_rotate(
        self, event_count: int, bytes_written: int, created_at: str
    ) -> bool:
        if event_count >= self.max_events_per_segment:
            return True
        if bytes_written >= self.max_bytes_per_segment:
            return True
        try:
            created = datetime.fromisoformat(created_at)
            age = (datetime.now(timezone.utc) - created).total_seconds()
            if age >= self.max_segment_age_seconds:
                return True
        except ValueError:
            pass
        return False


class LogAppender:
    """Append-only writer that rotates into numbered segments on disk.

    Directory layout::

        <log_dir>/
          segment-00001.log          (jsonl events, one per line)
          segment-00001.sig.json     (signed SegmentHeader)
          segment-00002.log
          segment-00002.sig.json
          ...

    Segments chain via previous_segment_root in the header.
    """

    def __init__(
        self,
        log_dir: str,
        signer: AgentIdentity,
        log_id: str | None = None,
        rotation: RotationPolicy | None = None,
    ) -> None:
        os.makedirs(log_dir, exist_ok=True)
        self.log_dir = log_dir
        self.signer = signer
        self.log_id = log_id or f"urn:pqc-audit-log:{uuid.uuid4().hex}"
        self.rotation = rotation or RotationPolicy()

        # State
        self._current_segment_number: int = self._detect_next_segment_number()
        self._current_events: list[InferenceEvent] = []
        self._current_created_at: str = datetime.now(timezone.utc).isoformat()
        self._current_bytes_written: int = 0
        self._previous_segment_root: str = self._read_previous_segment_root()

        # Open jsonl file for current segment
        self._jsonl_path = self._segment_jsonl_path(self._current_segment_number)
        self._jsonl_file = open(self._jsonl_path, "a", encoding="utf-8")
        self._sealed = False

    # -- paths --------------------------------------------------------------

    def _segment_jsonl_path(self, n: int) -> str:
        return os.path.join(self.log_dir, f"segment-{n:05d}.log")

    def _segment_sig_path(self, n: int) -> str:
        return os.path.join(self.log_dir, f"segment-{n:05d}.sig.json")

    # -- state recovery -----------------------------------------------------

    def _detect_next_segment_number(self) -> int:
        max_n = 0
        names = os.listdir(self.log_dir) if os.path.isdir(self.log_dir) else []
        for name in names:
            if name.startswith("segment-") and name.endswith(".sig.json"):
                try:
                    n = int(name[len("segment-"): len("segment-") + 5])
                    max_n = max(max_n, n)
                except ValueError:
                    continue
        return max_n + 1

    def _read_previous_segment_root(self) -> str:
        if self._current_segment_number <= 1:
            return ""
        prev_sig = self._segment_sig_path(self._current_segment_number - 1)
        if not os.path.exists(prev_sig):
            return ""
        try:
            with open(prev_sig, "r", encoding="utf-8") as f:
                data = json.load(f)
            return str(data.get("merkle_root", ""))
        except (OSError, json.JSONDecodeError):
            return ""

    # -- append / rotate ----------------------------------------------------

    def append(self, event: InferenceEvent) -> None:
        if self._sealed:
            raise AppendToSealedSegmentError("cannot append to a closed appender")
        line = event.to_jsonl() + "\n"
        self._jsonl_file.write(line)
        self._jsonl_file.flush()
        try:
            os.fsync(self._jsonl_file.fileno())
        except (OSError, ValueError):
            pass
        self._current_events.append(event)
        self._current_bytes_written += len(line.encode("utf-8"))

        if self.rotation.should_rotate(
            len(self._current_events),
            self._current_bytes_written,
            self._current_created_at,
        ):
            self.seal_current_segment()

    def seal_current_segment(self) -> SegmentHeader | None:
        """Seal the current segment with a signed header and start a new one."""
        if not self._current_events:
            return None

        header = SegmentHeader(
            segment_id=f"segment-{self._current_segment_number:05d}",
            segment_number=self._current_segment_number,
            created_at=self._current_created_at,
            sealed_at=datetime.now(timezone.utc).isoformat(),
            event_count=len(self._current_events),
            merkle_root="",
            previous_segment_root=self._previous_segment_root,
            log_id=self.log_id,
        )
        segment = AuditSegment(header=header, events=list(self._current_events))
        segment.recompute_root()

        digest = hashlib.sha3_256(header.canonical_bytes()).digest()
        sig = sign(digest, self.signer.signing_keypair)
        header.signer_did = self.signer.did
        header.algorithm = self.signer.signing_keypair.algorithm.value
        header.signature = sig.hex()
        header.public_key = self.signer.signing_keypair.public_key.hex()

        sig_path = self._segment_sig_path(self._current_segment_number)
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(header.to_dict(), f, indent=2)

        # Close current jsonl file
        self._jsonl_file.close()

        # Roll over state for next segment
        self._previous_segment_root = header.merkle_root
        self._current_segment_number += 1
        self._current_events = []
        self._current_created_at = datetime.now(timezone.utc).isoformat()
        self._current_bytes_written = 0
        self._jsonl_path = self._segment_jsonl_path(self._current_segment_number)
        self._jsonl_file = open(self._jsonl_path, "a", encoding="utf-8")
        return header

    def close(self) -> SegmentHeader | None:
        """Seal the current segment (if any) and close the file."""
        header: SegmentHeader | None = None
        if self._current_events:
            header = self.seal_current_segment()
        self._sealed = True
        try:
            self._jsonl_file.close()
        except Exception:
            pass
        # Remove the empty jsonl file created for the rolled-over next segment
        try:
            if os.path.exists(self._jsonl_path) and os.path.getsize(self._jsonl_path) == 0:
                os.remove(self._jsonl_path)
        except OSError:
            pass
        return header

    def __enter__(self) -> LogAppender:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
