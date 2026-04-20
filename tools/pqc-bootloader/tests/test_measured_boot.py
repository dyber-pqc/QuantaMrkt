"""Tests for MeasuredBoot."""

from __future__ import annotations

from pqc_bootloader.measured_boot import BootStage, MeasuredBoot


def test_extend_updates_pcr_value_deterministically() -> None:
    a = MeasuredBoot()
    b = MeasuredBoot()
    a.extend(BootStage.BOOTLOADER, b"bootloader-bytes")
    b.extend(BootStage.BOOTLOADER, b"bootloader-bytes")
    assert a.pcr_value == b.pcr_value
    assert a.pcr_value != "0" * 64
    assert len(a.measurements) == 1
    assert a.measurements[0].stage == BootStage.BOOTLOADER


def test_same_measurements_produce_same_pcr() -> None:
    a = MeasuredBoot()
    b = MeasuredBoot()
    stages = [
        (BootStage.BOOTLOADER, b"boot"),
        (BootStage.KERNEL, b"kernel"),
        (BootStage.INITRD, b"initrd"),
        (BootStage.USERSPACE, b"user"),
    ]
    for stage, content in stages:
        a.extend(stage, content)
        b.extend(stage, content)
    assert a.pcr_value == b.pcr_value


def test_different_order_produces_different_pcr() -> None:
    a = MeasuredBoot()
    b = MeasuredBoot()
    a.extend(BootStage.BOOTLOADER, b"boot")
    a.extend(BootStage.KERNEL, b"kernel")
    b.extend(BootStage.KERNEL, b"kernel")
    b.extend(BootStage.BOOTLOADER, b"boot")
    assert a.pcr_value != b.pcr_value


def test_reset_clears_state() -> None:
    m = MeasuredBoot()
    m.extend(BootStage.BOOTLOADER, b"boot")
    m.extend(BootStage.KERNEL, b"kernel")
    assert m.pcr_value != "0" * 64
    assert len(m.measurements) == 2
    m.reset()
    assert m.pcr_value == "0" * 64
    assert m.measurements == []
