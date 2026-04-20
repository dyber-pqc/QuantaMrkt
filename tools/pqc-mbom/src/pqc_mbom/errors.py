"""Exception hierarchy for pqc-mbom."""

from __future__ import annotations


class MBOMError(Exception):
    """Base exception for all pqc-mbom errors."""


class InvalidMBOMError(MBOMError):
    """Raised when an MBOM document is malformed or missing required fields."""


class SignatureVerificationError(MBOMError):
    """Raised when an MBOM signature fails cryptographic verification."""


class ComponentError(MBOMError):
    """Raised when a ModelComponent is invalid or internally inconsistent."""


class MissingComponentError(ComponentError):
    """Raised when a referenced component is not present in the MBOM."""


class SPDXConversionError(MBOMError):
    """Raised when converting between MBOM and SPDX fails a schema check."""
