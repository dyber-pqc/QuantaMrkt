"""CLI configuration helpers.

Thin wrappers around the core keystore config that provide sensible
defaults for the CLI (API URL, auth token, etc.).
"""

from __future__ import annotations

from quantumshield.core.keystore import load_config, save_config

DEFAULT_API_URL = "https://quantamrkt.com"


def get_api_url() -> str:
    """Return the configured API URL (default: https://quantamrkt.com)."""
    return load_config("api_url") or DEFAULT_API_URL


def get_auth_token() -> str | None:
    """Return the stored auth token, or None if not logged in."""
    return load_config("auth_token")


def set_auth_token(token: str) -> None:
    """Persist the auth token."""
    save_config("auth_token", token)


def is_logged_in() -> bool:
    """Return True if an auth token is stored."""
    return get_auth_token() is not None
