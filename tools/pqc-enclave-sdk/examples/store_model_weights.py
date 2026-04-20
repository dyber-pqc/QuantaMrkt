"""Store a 256 KB block of model weights in an in-memory enclave vault.

Demonstrates the full lifecycle: unlock -> put -> save -> lock -> unlock -> get.
The InMemoryEnclaveBackend is used so the example runs without any platform
secure element. A production deployment swaps in iOSEnclaveBackend,
AndroidEnclaveBackend, or QSEEBackend.
"""

from __future__ import annotations

import os

from pqc_enclave_sdk import (
    ArtifactKind,
    EnclaveVault,
    InMemoryEnclaveBackend,
)


def main() -> None:
    weights = os.urandom(256 * 1024)  # 256 KB simulated INT4 weights
    backend = InMemoryEnclaveBackend(
        device_id="iphone-alice-demo",
        device_model="iphone-15-pro",
    )

    vault = EnclaveVault(backend=backend)
    vault.unlock()
    print(f"[unlock] vault unlocked. key_id={vault._key_id}")

    enc = vault.put_artifact(
        name="llama-3.2-1b-int4",
        kind=ArtifactKind.MODEL_WEIGHTS,
        content=weights,
        version="1.0.0",
        app_bundle_id="com.example.localllm",
        tags=("prod", "int4"),
        description="Llama 3.2 1B INT4 weights for on-device inference.",
    )
    print(
        f"[put]    artifact_id={enc.metadata.artifact_id} "
        f"size={enc.metadata.size_bytes} bytes "
        f"sha3={enc.content_hash[:16]}..."
    )

    vault.save()
    print("[save]   encrypted store persisted to backend")

    # Preserve the session key so a fresh vault unlock can still decrypt
    # the persisted artifact. In a real deployment the enclave holds the
    # wrapping KEK and re-derives the same session key on next unlock.
    saved_key = vault._symmetric_key
    saved_key_id = vault._key_id
    saved_exp = vault._expires_at

    vault.lock()
    print("[lock]   vault sealed")

    vault2 = EnclaveVault(backend=backend)
    vault2.unlock()
    vault2._symmetric_key = saved_key
    vault2._key_id = saved_key_id
    vault2._expires_at = saved_exp
    vault2._store = backend.load_artifacts()
    print("[unlock] fresh vault over same backend")

    art = vault2.get_artifact("llama-3.2-1b-int4")
    assert art.content == weights
    print(f"[get]    decrypted {len(art.content)} bytes, match={art.content == weights}")


if __name__ == "__main__":
    main()
