"""GPU backend base class - wraps the host's GPU runtime API."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pqc_gpu_driver.tensor import EncryptedTensor


class GPUBackend(ABC):
    """Abstract base for GPU runtime backends.

    A backend's job is to move EncryptedTensors between CPU and GPU memory.
    The framework does NOT decrypt on the backend side - decryption is the
    session's responsibility. Backends only move bytes.
    """

    name: str = ""
    device_type: str = ""           # "cuda" | "rocm" | "in-memory" | ...

    @abstractmethod
    def upload(self, tensor: EncryptedTensor) -> str:
        """Copy an encrypted tensor to device memory. Returns device_handle."""

    @abstractmethod
    def download(self, device_handle: str) -> EncryptedTensor:
        """Copy an encrypted tensor from device memory back to host."""

    @abstractmethod
    def free(self, device_handle: str) -> None:
        """Free device memory associated with the handle."""

    @abstractmethod
    def device_info(self) -> dict:
        """Return a dict describing the device (name, compute_capability, memory)."""
