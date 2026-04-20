"""Exception hierarchy for pqc-reasoning-ledger."""

from __future__ import annotations


class ReasoningLedgerError(Exception):
    """Base exception for all pqc-reasoning-ledger errors."""


class ChainBrokenError(ReasoningLedgerError):
    """Raised when a step's previous_step_hash does not match the current chain tip,
    or when step ordering/linkage is otherwise inconsistent."""


class StepVerificationError(ReasoningLedgerError):
    """Raised when a step's declared step_hash does not match its recomputed hash."""


class TraceSealedError(ReasoningLedgerError):
    """Raised when attempting to append to a trace that has already been sealed."""


class InvalidStepError(ReasoningLedgerError):
    """Raised when a step is structurally invalid (bad kind, bad confidence, etc.)."""


class StepNotFoundError(ReasoningLedgerError):
    """Raised when a referenced step_id does not exist in a trace."""


class SignatureVerificationError(ReasoningLedgerError):
    """Raised when a SealedTrace's ML-DSA signature fails to verify,
    or a full verification result is not fully_verified."""
