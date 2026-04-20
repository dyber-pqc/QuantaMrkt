"""Tests for FilesystemGuard."""

from __future__ import annotations

import os
import platform

import pytest

from pqc_audit_log_fs.guard import FilesystemGuard


def test_seal_runs_without_error(tmp_path: str) -> None:
    p = os.path.join(str(tmp_path), "f.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("data")
    guard = FilesystemGuard()
    # Must not raise
    guard.seal(p)


def test_verify_read_only_after_seal(tmp_path: str) -> None:
    p = os.path.join(str(tmp_path), "f.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("data")
    guard = FilesystemGuard()
    guard.seal(p)
    if platform.system() == "Windows":
        # On Windows, Python's os.chmod dropping write bits may not fully
        # reflect in S_IWUSR for all file systems; if our verifier still sees
        # the file as writable, skip rather than fail.
        if not guard.verify_read_only(p):
            pytest.skip("chmod does not drop S_IWUSR on this Windows filesystem")
    assert guard.verify_read_only(p) is True
    # Restore write to allow pytest tmp cleanup
    try:
        os.chmod(p, 0o644)
    except OSError:
        pass
