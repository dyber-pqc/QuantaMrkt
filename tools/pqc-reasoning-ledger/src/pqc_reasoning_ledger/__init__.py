"""PQC Neurosymbolic Reasoning Ledger - quantum-safe chain-of-thought signing."""

from pqc_reasoning_ledger.errors import (
    ChainBrokenError,
    InvalidStepError,
    ReasoningLedgerError,
    SignatureVerificationError,
    StepNotFoundError,
    StepVerificationError,
    TraceSealedError,
)
from pqc_reasoning_ledger.merkle import (
    InclusionProof,
    build_proof,
    compute_merkle_root,
    verify_inclusion,
)
from pqc_reasoning_ledger.proof import ReasoningProver, StepInclusionProof
from pqc_reasoning_ledger.recorder import ReasoningRecorder
from pqc_reasoning_ledger.step import ReasoningStep, StepKind, StepReference
from pqc_reasoning_ledger.trace import ReasoningTrace, SealedTrace, TraceMetadata
from pqc_reasoning_ledger.verifier import TraceVerifier, VerificationResult

__version__ = "0.1.0"
__all__ = [
    "ReasoningStep",
    "StepKind",
    "StepReference",
    "ReasoningTrace",
    "TraceMetadata",
    "SealedTrace",
    "ReasoningRecorder",
    "TraceVerifier",
    "VerificationResult",
    "compute_merkle_root",
    "InclusionProof",
    "build_proof",
    "verify_inclusion",
    "StepInclusionProof",
    "ReasoningProver",
    "ReasoningLedgerError",
    "ChainBrokenError",
    "StepVerificationError",
    "TraceSealedError",
    "InvalidStepError",
    "StepNotFoundError",
    "SignatureVerificationError",
]
