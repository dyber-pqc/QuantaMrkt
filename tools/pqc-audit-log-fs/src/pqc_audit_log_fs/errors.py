"""Exception hierarchy for pqc-audit-log-fs."""

from __future__ import annotations


class AuditLogError(Exception):
    """Base exception for all pqc-audit-log-fs errors."""


class AppendToSealedSegmentError(AuditLogError):
    """Raised when attempting to append to a sealed or closed segment."""


class SegmentCorruptedError(AuditLogError):
    """Raised when a segment's merkle root does not match its recomputed root,
    or when a segment jsonl file contains malformed data."""


class SignatureVerificationError(AuditLogError):
    """Raised when a segment header's ML-DSA signature fails to verify."""


class ChainBrokenError(AuditLogError):
    """Raised when a segment's previous_segment_root does not match the
    preceding segment's merkle_root."""


class SegmentNotFoundError(AuditLogError):
    """Raised when a referenced segment (or event within) does not exist."""


class ImmutabilityViolationError(AuditLogError):
    """Raised when the FilesystemGuard cannot enforce immutability (strict mode)."""
