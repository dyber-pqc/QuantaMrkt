"""PQC Signed AI Content Provenance -- C2PA-compatible manifests with ML-DSA."""

from pqc_content_provenance.assertions.ai_generated import AIGeneratedAssertion
from pqc_content_provenance.assertions.base import Assertion
from pqc_content_provenance.assertions.training import TrainingAssertion
from pqc_content_provenance.assertions.usage import UsageAssertion
from pqc_content_provenance.chain import ProvenanceChain, ProvenanceLink
from pqc_content_provenance.embed import embed_manifest, extract_manifest
from pqc_content_provenance.errors import (
    ChainBrokenError,
    InvalidManifestError,
    ProvenanceError,
    SignatureVerificationError,
    UnknownAssertionError,
)
from pqc_content_provenance.manifest import (
    ContentManifest,
    GenerationContext,
    ModelAttribution,
)
from pqc_content_provenance.signer import ManifestSigner, VerificationResult

__version__ = "0.1.0"
__all__ = [
    "ContentManifest",
    "ModelAttribution",
    "GenerationContext",
    "Assertion",
    "TrainingAssertion",
    "UsageAssertion",
    "AIGeneratedAssertion",
    "ManifestSigner",
    "VerificationResult",
    "ProvenanceChain",
    "ProvenanceLink",
    "embed_manifest",
    "extract_manifest",
    "ProvenanceError",
    "InvalidManifestError",
    "SignatureVerificationError",
    "ChainBrokenError",
    "UnknownAssertionError",
]
