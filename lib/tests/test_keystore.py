"""Tests for the local keystore (save/load identity round trip)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.keys import generate_signing_keypair
from quantumshield.core.keystore import (
    KEYS_DIR,
    _load_all_config,
    get_default_identity,
    list_identities,
    load_config,
    load_identity,
    save_config,
    save_identity,
    set_default_identity,
)


@pytest.fixture(autouse=True)
def _isolate_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect keystore dirs to a temp directory for each test."""
    import quantumshield.core.keystore as ks

    tmp_keys = tmp_path / "keys"
    tmp_keys.mkdir()
    tmp_config = tmp_path / "config.json"

    monkeypatch.setattr(ks, "KEYSTORE_DIR", tmp_path)
    monkeypatch.setattr(ks, "KEYS_DIR", tmp_keys)
    monkeypatch.setattr(ks, "CONFIG_FILE", tmp_config)


class TestIdentityRoundTrip:
    def test_save_and_load_identity(self):
        kp = generate_signing_keypair(SignatureAlgorithm.ML_DSA_65)
        did = "did:pqaid:abc123"

        save_identity("alice", kp, did)
        loaded_kp, loaded_did = load_identity("alice")

        assert loaded_did == did
        assert loaded_kp.public_key == kp.public_key
        assert loaded_kp.private_key == kp.private_key
        assert loaded_kp.algorithm == kp.algorithm

    def test_load_missing_identity_raises(self):
        with pytest.raises(FileNotFoundError):
            load_identity("nonexistent")

    def test_list_identities(self):
        kp1 = generate_signing_keypair()
        kp2 = generate_signing_keypair(SignatureAlgorithm.ML_DSA_87)
        save_identity("alice", kp1, "did:pqaid:aaa")
        save_identity("bob", kp2, "did:pqaid:bbb")

        ids = list_identities()
        names = [i["name"] for i in ids]
        assert "alice" in names
        assert "bob" in names

    def test_default_identity(self):
        kp = generate_signing_keypair()
        save_identity("main", kp, "did:pqaid:main")
        set_default_identity("main")

        result = get_default_identity()
        assert result is not None
        loaded_kp, loaded_did = result
        assert loaded_did == "did:pqaid:main"
        assert loaded_kp.public_key == kp.public_key

    def test_default_identity_none_when_unset(self):
        assert get_default_identity() is None


class TestConfig:
    def test_save_and_load_config(self):
        save_config("api_url", "https://example.com")
        assert load_config("api_url") == "https://example.com"

    def test_load_missing_key_returns_none(self):
        assert load_config("nonexistent") is None

    def test_overwrite_config(self):
        save_config("key", "value1")
        save_config("key", "value2")
        assert load_config("key") == "value2"
