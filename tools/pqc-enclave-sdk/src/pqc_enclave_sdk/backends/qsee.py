"""Qualcomm Secure Execution Environment (QSEE) backend (stub interface).

Real integration uses Qualcomm's QSEE trusted application framework on
Snapdragon SoCs. This stub documents the expected shape; OEMs plug in
their signed Trusted App (TA) running inside the QSEE enclave.

A production implementation of this backend is expected to:

* Load a signed Trusted Application into QSEE via ``QSEECom_start_app``.
  The TA implements session-key wrapping + AES-GCM on the secure side and
  is the only code that ever touches the plaintext symmetric key.
* For :meth:`store_session_key`, send the 32-byte key over the QSEECom
  SMC channel wrapped with a TA-resident KEK; persist the wrapped blob
  in Android Keystore with the TA's key alias.
* For :meth:`load_session_key`, issue a QSEECom request that asks the TA
  to unwrap into its own memory and return a session handle (not the raw
  key). The vault then feeds ciphertext into the TA for decryption.
* For :meth:`save_artifacts` / :meth:`load_artifacts`, write the
  encrypted artifact store under the app's private data dir; QSEE only
  holds the key, not the ciphertext blobs.
* Use Qualcomm's Secure Processor (SPU) on newer Snapdragon parts for
  additional isolation of the KEK against side-channel attacks.

ML-KEM-768 / ML-DSA support is shipping in Qualcomm Crypto Engine
revisions; integrate that path when generating the session KEM keypair
currently done in-process.
"""

from __future__ import annotations

from pqc_enclave_sdk.artifact import EncryptedArtifact
from pqc_enclave_sdk.backends.base import EnclaveBackend
from pqc_enclave_sdk.errors import BackendError


class QSEEBackend(EnclaveBackend):
    """Stub Qualcomm Secure Execution Environment backend.

    Raises :class:`BackendError` when invoked without a signed Trusted
    Application loaded into QSEE.
    """

    name = "qualcomm-qsee"
    platform = "qsee"
    enclave_vendor = "qualcomm-qsee"

    def __init__(
        self,
        device_id: str = "snapdragon-unknown",
        device_model: str = "snapdragon-unknown",
        ta_name: str = "com.dyber.pqc.enclave.ta",
    ) -> None:
        self.device_id = device_id
        self.device_model = device_model
        self.ta_name = ta_name

    def store_session_key(self, key_id: str, key: bytes, expires_at: str) -> None:
        raise BackendError(
            "QSEEBackend.store_session_key is a stub. A real implementation "
            f"sends the key to the signed Trusted App {self.ta_name!r} loaded "
            "into QSEE via QSEECom_start_app + QSEECom_send_cmd."
        )

    def load_session_key(self, key_id: str) -> bytes | None:
        raise BackendError(
            "QSEEBackend.load_session_key is a stub. A real implementation "
            f"asks the {self.ta_name!r} TA to unwrap key {key_id} inside QSEE "
            "and returns only a session handle, never the raw bytes."
        )

    def save_artifacts(self, artifacts: dict[str, EncryptedArtifact]) -> None:
        raise BackendError(
            "QSEEBackend.save_artifacts is a stub. A real implementation writes "
            "the encrypted artifacts to the app's private data directory; QSEE "
            "only holds the wrapping key, not the ciphertext store."
        )

    def load_artifacts(self) -> dict[str, EncryptedArtifact]:
        raise BackendError(
            "QSEEBackend.load_artifacts is a stub. A real implementation reads "
            "the encrypted artifact file and deserializes it via "
            "EncryptedArtifact.from_dict."
        )
