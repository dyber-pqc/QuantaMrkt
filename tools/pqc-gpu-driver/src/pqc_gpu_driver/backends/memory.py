"""In-memory backend - reference implementation for tests and demos."""

from __future__ import annotations

import uuid

from pqc_gpu_driver.backends.base import GPUBackend
from pqc_gpu_driver.errors import BackendError
from pqc_gpu_driver.tensor import EncryptedTensor


class InMemoryBackend(GPUBackend):
    """Deterministic in-memory backend.

    Stores EncryptedTensor bundles in a dict keyed by a synthetic device handle.
    Suitable for tests, tutorials, and CI - has no dependency on any GPU runtime.
    The bytes stay encrypted; the backend never peeks inside the ciphertext.
    """

    name = "in-memory"
    device_type = "in-memory"

    def __init__(self, device_label: str = "simulated-gpu-0") -> None:
        self.device_label = device_label
        self._store: dict[str, EncryptedTensor] = {}

    def upload(self, tensor: EncryptedTensor) -> str:
        handle = f"mem:{uuid.uuid4().hex}"
        self._store[handle] = tensor
        return handle

    def download(self, device_handle: str) -> EncryptedTensor:
        if device_handle not in self._store:
            raise BackendError(f"unknown device handle {device_handle}")
        return self._store[device_handle]

    def free(self, device_handle: str) -> None:
        if device_handle not in self._store:
            raise BackendError(f"unknown device handle {device_handle}")
        del self._store[device_handle]

    def device_info(self) -> dict:
        return {
            "name": self.device_label,
            "device_type": self.device_type,
            "compute_capability": "n/a",
            "memory_bytes": sum(
                len(t.ciphertext) // 2 for t in self._store.values()
            ),
            "live_handles": len(self._store),
        }
