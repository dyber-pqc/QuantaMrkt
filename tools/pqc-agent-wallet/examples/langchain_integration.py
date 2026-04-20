"""Integrate wallet with a LangChain-style secret provider.

Run:  python examples/langchain_integration.py
"""

from __future__ import annotations

import tempfile

from quantumshield import AgentIdentity

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.integrations import (
    make_langchain_secret_provider,
    walletize_env,
)


def main() -> None:
    owner = AgentIdentity.create("langchain-agent")
    with tempfile.NamedTemporaryFile(suffix=".wallet", delete=False) as tmp:
        path = tmp.name

    w = Wallet.create_with_passphrase(path, "secret-phrase", owner)
    w.put("openai_api_key", "sk-langchain-demo", service="openai")
    w.put("serpapi_api_key", "sa-langchain-demo", service="serpapi")

    # Method 1: callable provider
    provider = make_langchain_secret_provider(w)
    print("[OK] openai via provider:", provider("openai_api_key"))

    # Method 2: bulk env mapping
    env_cfg = walletize_env(
        w,
        {
            "OPENAI_API_KEY": "openai_api_key",
            "SERPAPI_API_KEY": "serpapi_api_key",
        },
    )
    for k, v in env_cfg.items():
        print(f"[OK] {k} = {v}")


if __name__ == "__main__":
    main()
