"""Basic usage: create wallet, add credentials, reload and read.

Run:  python examples/basic_usage.py
"""

from __future__ import annotations

import tempfile

from quantumshield import AgentIdentity

from pqc_agent_wallet import Wallet


def main() -> None:
    owner = AgentIdentity.create("demo-agent")
    with tempfile.NamedTemporaryFile(suffix=".wallet", delete=False) as tmp:
        path = tmp.name

    # Create and populate
    w = Wallet.create_with_passphrase(path, "hunter2-demo", owner)
    w.put("openai_api_key", "sk-demo-openai", service="openai", tags=["prod"])
    w.put(
        "anthropic_api_key",
        "sk-demo-anthropic",
        service="anthropic",
        tags=["prod"],
    )
    w.put(
        "postgres_password",
        "demo-db-password",
        service="postgres",
        scheme="password",
    )
    print(f"Stored {len(w.list_names())} credentials: {w.list_names()}")
    w.save()
    w.lock()
    print(f"[OK] Wallet saved and locked at {path}")

    # Reload & unlock
    w2 = Wallet.load(path, owner)
    w2.unlock_with_passphrase("hunter2-demo")
    print("[OK] Wallet reloaded and unlocked.")
    print(f"openai_api_key    = {w2.get('openai_api_key')}")
    print(f"postgres_password = {w2.get('postgres_password')}")

    # Audit log
    print("\nAudit log (last 5):")
    for e in w2.audit.entries(limit=5):
        print(
            f"  [{e.timestamp}] {e.operation} {e.credential_name} success={e.success}"
        )


if __name__ == "__main__":
    main()
