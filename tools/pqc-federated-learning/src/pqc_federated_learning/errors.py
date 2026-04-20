"""Exception hierarchy for pqc-federated-learning."""

from __future__ import annotations


class FLError(Exception):
    """Base exception for all pqc-federated-learning errors."""


class InvalidUpdateError(FLError):
    """Raised when a client update is structurally invalid."""


class SignatureVerificationError(FLError):
    """Raised when a client update's signature fails to verify."""


class AggregationError(FLError):
    """Raised when aggregation cannot proceed (e.g., round/model mismatch)."""


class UntrustedClientError(FLError):
    """Raised when a client update is signed by a DID not in the trusted set."""


class ShapeMismatchError(FLError):
    """Raised when client tensors disagree on names or shapes."""


class InsufficientUpdatesError(FLError):
    """Raised when fewer than `min_updates` valid updates are available."""
