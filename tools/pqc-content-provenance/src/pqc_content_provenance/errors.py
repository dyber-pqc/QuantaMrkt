"""Exception hierarchy for PQC Content Provenance."""

from __future__ import annotations


class ProvenanceError(Exception):
    """Base exception for all content provenance errors."""


class InvalidManifestError(ProvenanceError):
    """Manifest structure is invalid or malformed."""


class SignatureVerificationError(ProvenanceError):
    """Cryptographic verification of a manifest signature failed."""


class ChainBrokenError(ProvenanceError):
    """A provenance chain link is missing or invalid."""


class UnknownAssertionError(ProvenanceError):
    """An assertion type is unknown or unregistered."""


class ContentHashMismatchError(SignatureVerificationError):
    """The content's actual hash doesn't match the manifest's claimed hash."""
