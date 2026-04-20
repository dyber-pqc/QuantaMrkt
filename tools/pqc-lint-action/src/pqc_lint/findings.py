"""Finding dataclass and severity levels."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"   # actively broken by known quantum attacks (RSA, ECDSA, DH, ECDH)
    HIGH = "high"           # vulnerable to future quantum attack, currently in use (DSA, old sig algos)
    MEDIUM = "medium"       # weak classical crypto (MD5, SHA-1)
    LOW = "low"             # style / best-practice (missing explicit algorithm, hard-coded key size)
    INFO = "info"           # informational (PQC-safe patterns detected)

    @property
    def order(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(
                f"Invalid severity '{value}'. Must be one of: "
                + ", ".join(s.value for s in cls)
            )


@dataclass
class Finding:
    """A single lint finding in a source file."""
    rule_id: str                # e.g. "PQC001"
    severity: Severity
    message: str                # short description
    file: str                   # path relative to scan root
    line: int                   # 1-based
    column: int = 1             # 1-based
    end_line: int | None = None
    end_column: int | None = None
    snippet: str = ""           # the exact matching text
    suggestion: str = ""        # PQC replacement hint
    cwe: str | None = None      # e.g. "CWE-327"
    language: str = ""          # python | javascript | go | rust | java | c

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(
            rule_id=data["rule_id"],
            severity=Severity.from_str(data["severity"]),
            message=data["message"],
            file=data["file"],
            line=data["line"],
            column=data.get("column", 1),
            end_line=data.get("end_line"),
            end_column=data.get("end_column"),
            snippet=data.get("snippet", ""),
            suggestion=data.get("suggestion", ""),
            cwe=data.get("cwe"),
            language=data.get("language", ""),
        )


@dataclass
class ScanReport:
    """Aggregate report of a scan session."""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    scan_root: str = "."
    started_at: str = ""
    duration_ms: int = 0

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def counts_by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
        return counts

    def has_failing(self, fail_on: Severity) -> bool:
        """True if any finding meets or exceeds the fail-on threshold."""
        return any(f.severity.order >= fail_on.order for f in self.findings)

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": "1.0",
                "scan_root": self.scan_root,
                "started_at": self.started_at,
                "duration_ms": self.duration_ms,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "counts_by_severity": self.counts_by_severity(),
                "counts_by_rule": self.counts_by_rule(),
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=2,
        )
