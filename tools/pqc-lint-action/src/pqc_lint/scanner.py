"""Filesystem scanner."""

from __future__ import annotations

import fnmatch
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from pqc_lint.findings import Finding, ScanReport
from pqc_lint.patterns import ALL_MATCHERS, MATCHERS_BY_LANGUAGE, PatternMatcher
from pqc_lint.rules import RULE_BY_ID

DEFAULT_EXCLUDES = (
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/dist/**",
    "**/build/**",
    "**/.pytest_cache/**",
    "**/.ruff_cache/**",
    "**/*.min.js",
)

# Hard size cap so we don't try to scan 500 MB binaries
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


def _matches_any(path: str, globs: Iterable[str]) -> bool:
    normalized = path.replace(os.sep, "/")
    return any(fnmatch.fnmatch(normalized, g) for g in globs)


@dataclass
class Scanner:
    """Walks a directory and runs pattern matchers against each file."""
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES
    languages: tuple[str, ...] = ()          # empty = all
    matchers: list[PatternMatcher] = field(default_factory=list)
    max_file_size: int = MAX_FILE_SIZE_BYTES

    def __post_init__(self) -> None:
        if not self.matchers:
            if self.languages:
                self.matchers = [
                    MATCHERS_BY_LANGUAGE[lang]
                    for lang in self.languages
                    if lang in MATCHERS_BY_LANGUAGE
                ]
            else:
                self.matchers = list(ALL_MATCHERS)

    def _pick_matcher(self, path: str) -> PatternMatcher | None:
        for m in self.matchers:
            if m.matches_file(path):
                return m
        return None

    def scan_file(self, file_path: str, root: str | None = None) -> list[Finding]:
        matcher = self._pick_matcher(file_path)
        if not matcher:
            return []
        try:
            if os.path.getsize(file_path) > self.max_file_size:
                return []
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return []

        rel = os.path.relpath(file_path, root) if root else file_path
        rel = rel.replace(os.sep, "/")
        return list(matcher.scan(rel, content, RULE_BY_ID))

    def scan_path(self, path: str) -> ScanReport:
        started = time.time()
        report = ScanReport(
            scan_root=path,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        if os.path.isfile(path):
            root = os.path.dirname(path) or "."
            findings = self.scan_file(path, root=root)
            report.findings.extend(findings)
            report.files_scanned += 1
            report.duration_ms = int((time.time() - started) * 1000)
            return report

        for dirpath, dirnames, filenames in os.walk(path):
            # prune directories matching excludes
            kept_dirs = []
            for d in dirnames:
                candidate = os.path.join(dirpath, d)
                if not _matches_any(candidate, self.excludes):
                    kept_dirs.append(d)
            dirnames[:] = kept_dirs

            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                if _matches_any(fp, self.excludes):
                    report.files_skipped += 1
                    continue
                matcher = self._pick_matcher(fp)
                if not matcher:
                    report.files_skipped += 1
                    continue
                findings = self.scan_file(fp, root=path)
                report.findings.extend(findings)
                report.files_scanned += 1

        report.duration_ms = int((time.time() - started) * 1000)
        return report
