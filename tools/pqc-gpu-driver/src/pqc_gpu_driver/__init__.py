"""PQC-Hardened GPU Driver - encrypted CPU-GPU tensor transfers with ML-KEM + AES-GCM."""

from pqc_gpu_driver.backends.base import GPUBackend
from pqc_gpu_driver.backends.cuda import CUDABackend
from pqc_gpu_driver.backends.memory import InMemoryBackend
from pqc_gpu_driver.backends.rocm import ROCmBackend
from pqc_gpu_driver.channel import ChannelSession, establish_channel
from pqc_gpu_driver.driver_attest import (
    DriverAttestation,
    DriverAttestationVerifier,
    DriverAttester,
    DriverModule,
)
from pqc_gpu_driver.errors import (
    BackendError,
    ChannelEstablishmentError,
    ChannelExpiredError,
    DecryptionError,
    DriverAttestationError,
    GPUDriverError,
    NonceReplayError,
)
from pqc_gpu_driver.tensor import EncryptedTensor, TensorMetadata

__version__ = "0.1.0"
__all__ = [
    "EncryptedTensor",
    "TensorMetadata",
    "ChannelSession",
    "establish_channel",
    "DriverModule",
    "DriverAttestation",
    "DriverAttester",
    "DriverAttestationVerifier",
    "GPUBackend",
    "InMemoryBackend",
    "CUDABackend",
    "ROCmBackend",
    "GPUDriverError",
    "ChannelEstablishmentError",
    "ChannelExpiredError",
    "NonceReplayError",
    "DecryptionError",
    "DriverAttestationError",
    "BackendError",
]
