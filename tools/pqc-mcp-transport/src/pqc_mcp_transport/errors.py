"""Custom exceptions for PQC MCP Transport."""

from __future__ import annotations


class PQCTransportError(Exception):
    """Base exception for all PQC transport errors."""


class SignatureVerificationError(PQCTransportError):
    """Raised when a PQC signature fails verification."""


class HandshakeError(PQCTransportError):
    """Raised when the PQC handshake fails."""


class SessionExpiredError(PQCTransportError):
    """Raised when a PQC session has timed out."""


class ReplayAttackError(PQCTransportError):
    """Raised when a nonce has already been used (potential replay attack)."""


class PeerNotAuthenticatedError(PQCTransportError):
    """Raised when an operation requires an authenticated session but none exists."""
