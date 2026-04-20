"""Android StrongBox + Keystore backend (stub interface).

Real integration uses the AndroidKeyStore provider with StrongBox where
available (Pixel Titan M, Samsung Knox Vault, etc.). This stub documents
the expected shape; app developers plug in their Kotlin / JNI bridge.

A production implementation of this backend is expected to:

* Request a hardware-backed key via ``KeyGenParameterSpec.Builder`` with
  ``setIsStrongBoxBacked(true)`` so the private key material lives in the
  dedicated StrongBox secure element, not the TEE.
* For :meth:`store_session_key`, wrap the 32-byte AES-GCM session key with
  the StrongBox key (``Cipher.WRAP_MODE`` over AES-GCM) and persist the
  wrapped bytes to EncryptedSharedPreferences or the app's private files
  directory.
* For :meth:`load_session_key`, unwrap the blob inside StrongBox via
  ``Cipher.UNWRAP_MODE`` - the plaintext symmetric key never leaves the
  secure element.
* Set ``setUserAuthenticationRequired(true)`` and ``setUnlockedDeviceRequired(true)``
  to require biometric or device credential before the key is usable.
* For :meth:`save_artifacts` and :meth:`load_artifacts`, serialize the
  encrypted artifact store to a file under ``Context.filesDir`` and wrap
  reads/writes in EncryptedFile from androidx.security.

ML-KEM-768 is available in BoringSSL and is being integrated into
AndroidKeyStore - plug that in where ``generate_kem_keypair`` currently
runs in-process.
"""

from __future__ import annotations

from pqc_enclave_sdk.artifact import EncryptedArtifact
from pqc_enclave_sdk.backends.base import EnclaveBackend
from pqc_enclave_sdk.errors import BackendError


class AndroidEnclaveBackend(EnclaveBackend):
    """Stub Android StrongBox / Keystore backend.

    Raises :class:`BackendError` when invoked without real Keystore wiring.
    """

    name = "android-strongbox"
    platform = "android"
    enclave_vendor = "android-strongbox"

    KEY_STORE_PROVIDER = "AndroidKeyStore"

    def __init__(
        self,
        device_id: str = "android-unknown",
        device_model: str = "android-unknown",
        keystore_alias: str = "com.dyber.pqc.enclave.session",
    ) -> None:
        self.device_id = device_id
        self.device_model = device_model
        self.keystore_alias = keystore_alias

    def store_session_key(self, key_id: str, key: bytes, expires_at: str) -> None:
        raise BackendError(
            "AndroidEnclaveBackend.store_session_key is a stub. A real "
            f"implementation wraps the 32-byte key with the {self.keystore_alias!r} "
            f"key in the {self.KEY_STORE_PROVIDER} provider (StrongBox-backed) "
            "and persists the wrapped blob."
        )

    def load_session_key(self, key_id: str) -> bytes | None:
        raise BackendError(
            "AndroidEnclaveBackend.load_session_key is a stub. A real "
            f"implementation unwraps the blob via Cipher.UNWRAP_MODE on the "
            f"{self.keystore_alias!r} StrongBox key for key_id {key_id}."
        )

    def save_artifacts(self, artifacts: dict[str, EncryptedArtifact]) -> None:
        raise BackendError(
            "AndroidEnclaveBackend.save_artifacts is a stub. A real implementation "
            "persists the encrypted artifacts via androidx.security.EncryptedFile "
            "under Context.filesDir."
        )

    def load_artifacts(self) -> dict[str, EncryptedArtifact]:
        raise BackendError(
            "AndroidEnclaveBackend.load_artifacts is a stub. A real implementation "
            "reads the EncryptedFile back and deserializes it via "
            "EncryptedArtifact.from_dict."
        )
