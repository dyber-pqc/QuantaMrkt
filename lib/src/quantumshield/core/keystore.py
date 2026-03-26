"""Local key storage at ~/.quantumshield/.

Provides persistent storage for agent identities (signing keypairs + DIDs)
and application configuration (API URL, auth tokens, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.keys import SigningKeypair

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
KEYSTORE_DIR = Path.home() / ".quantumshield"
KEYS_DIR = KEYSTORE_DIR / "keys"
CONFIG_FILE = KEYSTORE_DIR / "config.json"


def _ensure_dirs() -> None:
    """Create the keystore directories if they don't exist."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Identity management
# ---------------------------------------------------------------------------


def save_identity(name: str, keypair: SigningKeypair, did: str) -> Path:
    """Persist a signing identity to disk.

    Keys are stored as hex-encoded JSON at ``~/.quantumshield/keys/<name>.json``.

    Args:
        name: Human-readable identity name (used as filename stem).
        keypair: The signing keypair to store.
        did: The DID associated with this identity.

    Returns:
        The path to the saved identity file.
    """
    _ensure_dirs()
    data = {
        "name": name,
        "did": did,
        "algorithm": keypair.algorithm.value,
        "public_key": keypair.public_key.hex(),
        "private_key": keypair.private_key.hex(),
    }
    path = KEYS_DIR / f"{name}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def load_identity(name: str) -> tuple[SigningKeypair, str]:
    """Load a signing identity from disk.

    Args:
        name: The identity name to load.

    Returns:
        A tuple of (SigningKeypair, did).

    Raises:
        FileNotFoundError: If the identity does not exist.
    """
    path = KEYS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Identity '{name}' not found at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    algorithm = SignatureAlgorithm(data["algorithm"])
    keypair = SigningKeypair(
        public_key=bytes.fromhex(data["public_key"]),
        private_key=bytes.fromhex(data["private_key"]),
        algorithm=algorithm,
    )
    return keypair, data["did"]


def list_identities() -> list[dict[str, Any]]:
    """List all saved identities.

    Returns:
        A list of dicts with ``name``, ``did``, and ``algorithm`` for each identity.
    """
    _ensure_dirs()
    identities: list[dict[str, Any]] = []
    for path in sorted(KEYS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            identities.append({
                "name": data["name"],
                "did": data["did"],
                "algorithm": data["algorithm"],
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return identities


def get_default_identity() -> tuple[SigningKeypair, str] | None:
    """Return the default identity, or None if not set.

    The default identity name is stored in the config under ``default_identity``.
    """
    default_name = load_config("default_identity")
    if default_name is None:
        return None
    try:
        return load_identity(default_name)
    except FileNotFoundError:
        return None


def set_default_identity(name: str) -> None:
    """Set *name* as the default identity.

    Args:
        name: The identity name to make default.

    Raises:
        FileNotFoundError: If the identity does not exist.
    """
    path = KEYS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Identity '{name}' not found at {path}")
    save_config("default_identity", name)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_all_config() -> dict[str, Any]:
    _ensure_dirs()
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    return {}


def _save_all_config(cfg: dict[str, Any]) -> None:
    _ensure_dirs()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def save_config(key: str, value: str) -> None:
    """Persist a single config value.

    Args:
        key: Config key (e.g. ``api_url``, ``auth_token``).
        value: The value to store.
    """
    cfg = _load_all_config()
    cfg[key] = value
    _save_all_config(cfg)


def load_config(key: str) -> str | None:
    """Load a single config value.

    Args:
        key: Config key to look up.

    Returns:
        The value, or None if not set.
    """
    return _load_all_config().get(key)
