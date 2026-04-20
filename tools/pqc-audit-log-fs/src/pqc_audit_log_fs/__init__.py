"""PQC Immutable AI Audit Log (Filesystem) - tamper-evident inference event log."""

from pqc_audit_log_fs.anchor import AnchorSink, MerkleAnchor
from pqc_audit_log_fs.appender import LogAppender, RotationPolicy
from pqc_audit_log_fs.errors import (
    AppendToSealedSegmentError,
    AuditLogError,
    ChainBrokenError,
    ImmutabilityViolationError,
    SegmentCorruptedError,
    SegmentNotFoundError,
    SignatureVerificationError,
)
from pqc_audit_log_fs.event import InferenceEvent
from pqc_audit_log_fs.guard import FilesystemGuard
from pqc_audit_log_fs.merkle import (
    InclusionProof,
    compute_merkle_root,
    verify_inclusion,
)
from pqc_audit_log_fs.prover import InclusionProver
from pqc_audit_log_fs.reader import LogReader
from pqc_audit_log_fs.segment import AuditSegment, SegmentHeader

__version__ = "0.1.0"

__all__ = [
    "InferenceEvent",
    "AuditSegment",
    "SegmentHeader",
    "compute_merkle_root",
    "InclusionProof",
    "verify_inclusion",
    "LogAppender",
    "RotationPolicy",
    "LogReader",
    "InclusionProver",
    "MerkleAnchor",
    "AnchorSink",
    "FilesystemGuard",
    "AuditLogError",
    "AppendToSealedSegmentError",
    "SegmentCorruptedError",
    "SignatureVerificationError",
    "ChainBrokenError",
    "SegmentNotFoundError",
    "ImmutabilityViolationError",
]
