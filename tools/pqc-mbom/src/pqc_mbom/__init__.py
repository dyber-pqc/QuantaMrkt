"""PQC AI MBOM - quantum-safe Model Bill of Materials."""

from pqc_mbom.errors import (
    MBOMError,
    InvalidMBOMError,
    SignatureVerificationError,
    ComponentError,
    MissingComponentError,
    SPDXConversionError,
)
from pqc_mbom.component import (
    ModelComponent,
    ComponentType,
    ComponentReference,
    LicenseInfo,
)
from pqc_mbom.mbom import MBOM, MBOMBuilder
from pqc_mbom.signer import MBOMSigner, MBOMVerifier, VerificationResult
from pqc_mbom.spdx import to_spdx_json, from_spdx_json
from pqc_mbom.diff import MBOMDiff, diff_mboms

__version__ = "0.1.0"
__all__ = [
    "MBOM", "MBOMBuilder",
    "ModelComponent", "ComponentType", "ComponentReference", "LicenseInfo",
    "MBOMSigner", "MBOMVerifier", "VerificationResult",
    "to_spdx_json", "from_spdx_json",
    "MBOMDiff", "diff_mboms",
    "MBOMError", "InvalidMBOMError", "SignatureVerificationError",
    "ComponentError", "MissingComponentError", "SPDXConversionError",
]
