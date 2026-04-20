"""Install an os.getenv shim so legacy code transparently uses the wallet.

Run:  python examples/env_shim_demo.py
"""

from __future__ import annotations

import os
import tempfile

from quantumshield import AgentIdentity

from pqc_agent_wallet import Wallet
from pqc_agent_wallet.integrations import install_env_shim


def main() -> None:
    owner = AgentIdentity.create("env-shim-agent")
    with tempfile.NamedTemporaryFile(suffix=".wallet", delete=False) as tmp:
        path = tmp.name

    w = Wallet.create_with_passphrase(path, "env-shim-pass", owner)
    w.put("my_api_key", "sk-env-shim-demo", service="demo")

    # Pretend a library we don't control does this:
    print("Before shim, os.getenv('my_api_key') =", os.getenv("my_api_key"))

    install_env_shim(w)
    print("After shim,  os.getenv('my_api_key') =", os.getenv("my_api_key"))


if __name__ == "__main__":
    main()
