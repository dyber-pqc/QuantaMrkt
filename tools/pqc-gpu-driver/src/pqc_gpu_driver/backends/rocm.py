"""ROCm backend (stub interface).

Real integration uses the AMD ROCm HIP runtime. This stub documents the
expected shape; users plug in their real syscalls.

A production implementation of this backend is expected to:

* Initialize a HIP context via ``hipInit`` / ``hipSetDevice`` for the target
  AMD GPU (MI300X, MI325X, or future CDNA-class device).
* For :meth:`upload`, allocate device memory with ``hipMalloc`` and copy the
  ciphertext bytes of the :class:`EncryptedTensor` from pinned host memory
  with ``hipMemcpy`` (host-to-device). Register the pointer with HIP-IPC if
  cross-process sharing is required.
* For :meth:`download`, issue ``hipMemcpy`` (device-to-host) from the device
  buffer associated with ``device_handle`` back into a host buffer and return
  it wrapped in an :class:`EncryptedTensor`.
* For :meth:`free`, call ``hipFree`` and drop the IPC handle.
* Keep tensor bytes encrypted at rest; plaintext exists only inside the
  workload's trusted compute boundary.
"""

from __future__ import annotations

from pqc_gpu_driver.backends.base import GPUBackend
from pqc_gpu_driver.errors import BackendError
from pqc_gpu_driver.tensor import EncryptedTensor


class ROCmBackend(GPUBackend):
    """Stub AMD ROCm backend.

    Raises :class:`BackendError` when invoked without real runtime wiring.
    """

    name = "rocm"
    device_type = "rocm"

    def __init__(self, device_index: int = 0) -> None:
        self.device_index = device_index

    def upload(self, tensor: EncryptedTensor) -> str:
        raise BackendError(
            "ROCmBackend.upload is a stub. A real implementation allocates "
            f"device memory on HIP device {self.device_index} via hipMalloc "
            "and copies the ciphertext bytes with hipMemcpy (HostToDevice)."
        )

    def download(self, device_handle: str) -> EncryptedTensor:
        raise BackendError(
            "ROCmBackend.download is a stub. A real implementation issues "
            f"hipMemcpy (DeviceToHost) for handle {device_handle} to pull "
            "ciphertext bytes back to host memory."
        )

    def free(self, device_handle: str) -> None:
        raise BackendError(
            "ROCmBackend.free is a stub. A real implementation calls hipFree "
            f"on the device pointer for {device_handle} and drops any "
            "HIP-IPC handles."
        )

    def device_info(self) -> dict:
        raise BackendError(
            "ROCmBackend.device_info is a stub. A real implementation reads "
            f"device {self.device_index} properties via hipGetDeviceProperties."
        )
