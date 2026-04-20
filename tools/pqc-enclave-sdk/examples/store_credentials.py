"""Store three API credentials for three different app bundles and list them."""

from __future__ import annotations

from pqc_enclave_sdk import (
    ArtifactKind,
    EnclaveVault,
    InMemoryEnclaveBackend,
)


def main() -> None:
    backend = InMemoryEnclaveBackend(
        device_id="pixel-8-bob-demo",
        device_model="pixel-8",
    )
    vault = EnclaveVault(backend=backend)
    vault.unlock()

    credentials = [
        ("openai_api_key", b"sk-openai-test", "com.example.chatapp"),
        ("anthropic_api_key", b"sk-ant-test", "com.example.chatapp"),
        ("stripe_secret", b"sk_live_stripe", "com.example.payments"),
    ]
    for name, value, bundle in credentials:
        vault.put_artifact(
            name=name,
            kind=ArtifactKind.CREDENTIAL,
            content=value,
            app_bundle_id=bundle,
        )
        print(f"[put]  stored {name!r} for bundle {bundle!r}")

    print()
    print("[list] artifacts in vault:")
    for meta in vault.list_artifacts():
        print(
            f"  - name={meta.name:<22} bundle={meta.app_bundle_id:<24} "
            f"size={meta.size_bytes:>3}B  kind={meta.kind.value}"
        )

    print()
    retrieved = vault.get_artifact("anthropic_api_key").content
    print(f"[get]  anthropic_api_key -> {retrieved!r}")


if __name__ == "__main__":
    main()
