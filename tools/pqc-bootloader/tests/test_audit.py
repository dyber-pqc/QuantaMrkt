"""Tests for BootAttestationLog."""

from __future__ import annotations

import json

from pqc_bootloader.audit import BootAttestationLog


def test_log_accept_and_reject_append() -> None:
    log = BootAttestationLog()
    log.log_accept("fw", "1.0.0", "ab" * 32, reason="all good")
    log.log_reject("fw", "1.0.1", "cd" * 32, reason="bad signature")
    entries = log.entries(limit=10)
    assert len(entries) == 2
    decisions = sorted(e.decision for e in entries)
    assert decisions == ["accept", "reject"]


def test_filter_by_decision() -> None:
    log = BootAttestationLog()
    log.log_accept("fw", "1.0.0", "ab" * 32)
    log.log_reject("fw", "1.0.1", "cd" * 32, reason="bad sig")
    log.log_accept("fw", "1.0.2", "ef" * 32)

    accepts = log.entries(decision="accept")
    rejects = log.entries(decision="reject")
    assert len(accepts) == 2
    assert len(rejects) == 1
    assert rejects[0].reason == "bad sig"


def test_max_entries_rotation() -> None:
    log = BootAttestationLog(max_entries=3)
    for i in range(5):
        log.log_accept("fw", f"1.0.{i}", f"{i:064x}")
    assert len(log) == 3
    # The first two should have rotated out; only 1.0.2, 1.0.3, 1.0.4 remain
    versions = sorted(e.firmware_version for e in log.entries(limit=10))
    assert versions == ["1.0.2", "1.0.3", "1.0.4"]


def test_export_json_valid() -> None:
    log = BootAttestationLog()
    log.log_accept("fw", "1.0.0", "ab" * 32, pcr_value_after="cd" * 32)
    log.log_reject("fw", "1.0.1", "ef" * 32, reason="unsigned")

    blob = log.export_json()
    parsed = json.loads(blob)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["decision"] == "accept"
    assert parsed[1]["decision"] == "reject"
