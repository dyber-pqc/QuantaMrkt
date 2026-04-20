"""Tests for suggestion mapping."""

from __future__ import annotations

from pqc_lint.suggestions import suggest_replacement


def test_suggest_rsa_returns_ml_dsa():
    assert "ML-DSA" in suggest_replacement("RSA-signing")


def test_suggest_ecdsa_returns_ml_dsa():
    assert "ML-DSA" in suggest_replacement("ECDSA")


def test_suggest_ecdh_returns_ml_kem():
    assert "ML-KEM" in suggest_replacement("ECDH")


def test_suggest_md5_returns_sha3():
    assert "SHA3" in suggest_replacement("MD5")


def test_suggest_unknown_returns_empty_string():
    assert suggest_replacement("NOT-A-REAL-PRIMITIVE-XYZ") == ""
