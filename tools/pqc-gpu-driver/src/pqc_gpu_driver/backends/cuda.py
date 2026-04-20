"""CUDA backend (stub interface).

Real integration uses the NVIDIA CUDA Driver / Runtime API. This stub
documents the expected shape; users plug in their real syscalls.

A production implementation of this backend is expected to:

* Initialize a CUDA context via ``cuInit`` / ``cuCtxCreate`` for the target
  device (typically an H100 or H200 with Confidential Computing enabled).
* For :meth:`upload`, allocate device memory with ``cuMemAlloc`` and copy the
  ciphertext bytes of the :class:`EncryptedTensor` from pinned host memory
  with ``cuMemcpyHtoD``. Register the pointer with CUDA-IPC if cross-process
  sharing is required.
* For :meth:`download`, issue ``cuMemcpyDtoH`` from the device buffer
  associated with ``device_handle`` back into a host buffer and return it
  wrapped in an :class:`EncryptedTensor`.
* For :meth:`free`, call ``cuMemFree`` and drop the IPC handle.
* Crucially, keep the tensor bytes encrypted at rest on device until the
  workload actively decrypts them in enclave memory (H100 Confidential
  Computing) - the framework never gives the host OS or hypervisor a view
  of plaintext.
"""

from __future__ import annotations

from pqc_gpu_driver.backends.base import GPUBackend
from pqc_gpu_driver.errors import BackendError
from pqc_gpu_driver.tensor import EncryptedTensor


class CUDABackend(GPUBackend):
    """Stub NVIDIA CUDA backend.

    Raises :class:`BackendError` when invoked without real runtime wiring.
    """

    name = "cuda"
    device_type = "cuda"

    def __init__(self, device_index: int = 0) -> None:
        self.device_index = device_index

    def upload(self, tensor: EncryptedTensor) -> str:
        raise BackendError(
            "CUDABackend.upload is a stub. A real implementation allocates "
            f"device memory on CUDA device {self.device_index} via cuMemAlloc "
            "and copies the ciphertext bytes with cuMemcpyHtoD."
        )

    def download(self, device_handle: str) -> EncryptedTensor:
        raise BackendError(
            "CUDABackend.download is a stub. A real implementation issues "
            f"cuMemcpyDtoH for handle {device_handle} to pull ciphertext "
            "bytes back to host memory."
        )

    def free(self, device_handle: str) -> None:
        raise BackendError(
            "CUDABackend.free is a stub. A real implementation calls "
            f"cuMemFree on the device pointer for {device_handle} and drops "
            "any CUDA-IPC handles."
        )

    def device_info(self) -> dict:
        raise BackendError(
            "CUDABackend.device_info is a stub. A real implementation reads "
            f"device {self.device_index} name + compute_capability via "
            "cuDeviceGetName and cuDeviceComputeCapability."
        )
