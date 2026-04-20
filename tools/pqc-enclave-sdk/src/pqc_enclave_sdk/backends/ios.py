"""iOS Secure Enclave backend (stub interface).

Real integration uses Apple's CryptoKit + Keychain Services. This stub
documents the expected shape; app developers plug in their Swift / ObjC
bridge layer.

A production implementation of this backend is expected to:

* Generate a hardware-backed key in the Secure Enclave with
  ``SecureEnclave.P256.KeyAgreement.PrivateKey`` (CryptoKit). The private
  key is non-extractable and bound to the device's SEP.
* For :meth:`store_session_key`, wrap the 32-byte AES-GCM session key with
  the SEP key via ``HPKE`` or ``AES.GCM.seal`` and persist the wrapped blob
  to the Keychain with ``kSecAttrTokenIDSecureEnclave`` and access-control
  flags ``kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage``.
* For :meth:`load_session_key`, query the Keychain for the wrapped key and
  unwrap it inside the SEP - the plaintext symmetric key never leaves
  enclave memory.
* For :meth:`save_artifacts` and :meth:`load_artifacts`, serialize the
  encrypted artifact store to a file in the app's Data Protection
  ``NSFileProtectionCompleteUntilFirstUserAuthentication`` container.
* Optionally attach a DeviceCheck / App Attest token to prove the binary
  is genuine and the device has not been jailbroken.

ML-KEM-768 support on iOS is arriving via Apple's PQ3 iMessage stack and
CryptoKit post-quantum primitives - plug that in where ``generate_kem_keypair``
currently runs in-process.
"""

from __future__ import annotations

from pqc_enclave_sdk.artifact import EncryptedArtifact
from pqc_enclave_sdk.backends.base import EnclaveBackend
from pqc_enclave_sdk.errors import BackendError


class iOSEnclaveBackend(EnclaveBackend):
    """Stub Apple Secure Enclave backend.

    Raises :class:`BackendError` when invoked without real SEP wiring.
    """

    name = "ios-secure-enclave"
    platform = "ios"
    enclave_vendor = "apple-se"

    def __init__(
        self,
        device_id: str = "iphone-unknown",
        device_model: str = "iphone-unknown",
        keychain_service: str = "com.dyber.pqc.enclave",
    ) -> None:
        self.device_id = device_id
        self.device_model = device_model
        self.keychain_service = keychain_service

    def store_session_key(self, key_id: str, key: bytes, expires_at: str) -> None:
        raise BackendError(
            "iOSEnclaveBackend.store_session_key is a stub. A real implementation "
            f"wraps the 32-byte key with a SecureEnclave.P256 key and writes the "
            f"wrapped blob to the Keychain service {self.keychain_service!r} with "
            "kSecAttrTokenIDSecureEnclave + access-control flags."
        )

    def load_session_key(self, key_id: str) -> bytes | None:
        raise BackendError(
            "iOSEnclaveBackend.load_session_key is a stub. A real implementation "
            f"queries the Keychain service {self.keychain_service!r} for key "
            f"{key_id} and unwraps the blob inside the SEP."
        )

    def save_artifacts(self, artifacts: dict[str, EncryptedArtifact]) -> None:
        raise BackendError(
            "iOSEnclaveBackend.save_artifacts is a stub. A real implementation "
            "serializes the encrypted artifacts to a file under "
            "NSFileProtectionCompleteUntilFirstUserAuthentication in the app's "
            "Data Protection container."
        )

    def load_artifacts(self) -> dict[str, EncryptedArtifact]:
        raise BackendError(
            "iOSEnclaveBackend.load_artifacts is a stub. A real implementation "
            "reads the encrypted artifact file back from the Data Protection "
            "container and deserializes it via EncryptedArtifact.from_dict."
        )
