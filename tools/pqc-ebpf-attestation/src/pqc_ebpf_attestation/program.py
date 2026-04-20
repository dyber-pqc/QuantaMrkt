"""eBPF program data structures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class BPFProgramType(str, Enum):
    """eBPF program attach types the verifier understands."""

    KPROBE = "kprobe"
    KRETPROBE = "kretprobe"
    TRACEPOINT = "tracepoint"
    XDP = "xdp"
    SOCKET_FILTER = "socket_filter"
    CGROUP_SKB = "cgroup_skb"
    LSM = "lsm"
    TRACING = "tracing"  # fentry/fexit
    PERF_EVENT = "perf_event"
    SCHED_CLS = "sched_cls"
    SYSCALL = "syscall"
    USER = "user"  # userspace helper
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BPFProgramMetadata:
    """Non-bytecode metadata about an eBPF program."""

    name: str
    program_type: BPFProgramType
    license: str = "GPL"
    author: str = ""
    description: str = ""
    version: str = ""
    kernel_min: str = ""  # e.g. "5.15"
    attach_point: str = ""  # e.g. "sys_bpf", "sys_enter_read"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["program_type"] = self.program_type.value
        return d


@dataclass
class BPFProgram:
    """A single eBPF program: bytecode + metadata + hash."""

    metadata: BPFProgramMetadata
    bytecode: bytes  # the raw ELF bytes or BPF instructions
    bytecode_hash: str = ""  # hex SHA3-256 of bytecode
    bytecode_size: int = 0

    @staticmethod
    def hash_bytecode(bytecode: bytes) -> str:
        return hashlib.sha3_256(bytecode).hexdigest()

    @classmethod
    def from_bytes(cls, metadata: BPFProgramMetadata, bytecode: bytes) -> BPFProgram:
        return cls(
            metadata=metadata,
            bytecode=bytecode,
            bytecode_hash=cls.hash_bytecode(bytecode),
            bytecode_size=len(bytecode),
        )

    @classmethod
    def from_file(cls, metadata: BPFProgramMetadata, path: str) -> BPFProgram:
        with open(path, "rb") as f:
            bytecode = f.read()
        return cls.from_bytes(metadata, bytecode)

    def canonical_manifest_bytes(self) -> bytes:
        """Deterministic bytes that are signed (metadata + hash, NOT raw bytecode)."""
        payload = {
            "metadata": self.metadata.to_dict(),
            "bytecode_hash": self.bytecode_hash,
            "bytecode_size": self.bytecode_size,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self, include_bytecode: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "metadata": self.metadata.to_dict(),
            "bytecode_hash": self.bytecode_hash,
            "bytecode_size": self.bytecode_size,
        }
        if include_bytecode:
            import base64

            d["bytecode_base64"] = base64.b64encode(self.bytecode).decode("ascii")
        return d
