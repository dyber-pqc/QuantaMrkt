"""PQC Secure Enclave SDK - quantum-safe on-device AI artifact storage."""

from pqc_enclave_sdk.artifact import (
    ArtifactKind,
    ArtifactMetadata,
    EnclaveArtifact,
    EncryptedArtifact,
)
from pqc_enclave_sdk.attestation import DeviceAttestation, DeviceAttester
from pqc_enclave_sdk.audit import EnclaveAuditEntry, EnclaveAuditLog
from pqc_enclave_sdk.backends.android import AndroidEnclaveBackend
from pqc_enclave_sdk.backends.base import EnclaveBackend
from pqc_enclave_sdk.backends.ios import iOSEnclaveBackend
from pqc_enclave_sdk.backends.memory import InMemoryEnclaveBackend
from pqc_enclave_sdk.backends.qsee import QSEEBackend
from pqc_enclave_sdk.errors import (
    AttestationError,
    BackendError,
    DecryptionError,
    EnclaveLockedError,
    EnclaveSDKError,
    PolicyViolationError,
    UnknownArtifactError,
)
from pqc_enclave_sdk.policy import AccessPolicy, ArtifactPolicy
from pqc_enclave_sdk.vault import EnclaveVault, establish_enclave_session

__version__ = "0.1.0"
__all__ = [
    "EnclaveArtifact",
    "ArtifactKind",
    "ArtifactMetadata",
    "EncryptedArtifact",
    "EnclaveVault",
    "establish_enclave_session",
    "AccessPolicy",
    "ArtifactPolicy",
    "DeviceAttestation",
    "DeviceAttester",
    "EnclaveAuditLog",
    "EnclaveAuditEntry",
    "EnclaveBackend",
    "InMemoryEnclaveBackend",
    "iOSEnclaveBackend",
    "AndroidEnclaveBackend",
    "QSEEBackend",
    "EnclaveSDKError",
    "UnknownArtifactError",
    "EnclaveLockedError",
    "DecryptionError",
    "BackendError",
    "AttestationError",
    "PolicyViolationError",
]
