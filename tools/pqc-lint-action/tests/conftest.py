"""Pytest fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture
def scan_tmpdir(tmp_path):
    """A temp directory that tests can populate with files then scan."""
    return tmp_path


@pytest.fixture
def sample_python_rsa():
    return (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )


@pytest.fixture
def sample_python_ecdsa():
    return (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "key = ec.generate_private_key(ec.SECP256R1())\n"
    )


@pytest.fixture
def sample_python_clean():
    return "def hello():\n    return 'pqc-safe code'\n"
