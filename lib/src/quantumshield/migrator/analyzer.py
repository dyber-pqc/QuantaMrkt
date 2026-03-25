"""Migration analysis engine for detecting quantum-vulnerable cryptography."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from quantumshield.migrator.patterns import VULNERABILITY_PATTERNS


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding in a source file."""

    file_path: str
    line_number: int
    pattern_name: str
    risk_level: str
    description: str
    replacement: str
    matched_text: str = ""


class MigrationReport(BaseModel):
    """Report from a migration analysis run."""

    files_scanned: int = 0
    files_with_crypto: int = 0
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    effort_estimate: str = "unknown"
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scan_path: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.risk_level == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.risk_level == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.risk_level == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.risk_level == "LOW")


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".kt", ".scala",
    ".go",
    ".rs",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".m", ".mm",
}

# Directories to skip
SKIP_DIRS = {
    "__pycache__", "node_modules", ".git", ".svn", ".hg",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache",
}


class MigrationAgent:
    """Analyzes codebases for quantum-vulnerable cryptographic patterns.

    Walks source files and applies regex-based pattern matching to detect
    usage of cryptographic primitives that are vulnerable to quantum attacks.
    """

    def __init__(self, patterns: Optional[dict] = None) -> None:
        """Initialize the migration agent.

        Args:
            patterns: Custom vulnerability patterns dict. Defaults to built-in patterns.
        """
        self.patterns = patterns or VULNERABILITY_PATTERNS
        self._compiled_patterns: dict[str, re.Pattern] = {}
        for name, info in self.patterns.items():
            self._compiled_patterns[name] = re.compile(info["pattern"], re.IGNORECASE)

    def analyze(self, path: str) -> MigrationReport:
        """Analyze a file or directory for quantum-vulnerable cryptography.

        Args:
            path: Path to a file or directory to scan.

        Returns:
            A MigrationReport with all findings.
        """
        target = Path(path)
        vulnerabilities: list[VulnerabilityFinding] = []
        files_scanned = 0
        files_with_crypto: set[str] = set()

        if target.is_file():
            findings = self._scan_file(str(target))
            files_scanned = 1
            if findings:
                files_with_crypto.add(str(target))
                vulnerabilities.extend(findings)
        elif target.is_dir():
            for root, dirs, filenames in os.walk(target):
                # Prune skipped directories
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

                for filename in sorted(filenames):
                    ext = Path(filename).suffix.lower()
                    if ext not in SCANNABLE_EXTENSIONS:
                        continue

                    file_path = os.path.join(root, filename)
                    files_scanned += 1
                    findings = self._scan_file(file_path)
                    if findings:
                        files_with_crypto.add(file_path)
                        vulnerabilities.extend(findings)
        else:
            raise FileNotFoundError(f"Path does not exist: {path}")

        effort = self._estimate_effort(vulnerabilities)

        return MigrationReport(
            files_scanned=files_scanned,
            files_with_crypto=len(files_with_crypto),
            vulnerabilities=vulnerabilities,
            effort_estimate=effort,
            scan_path=str(target),
        )

    def migrate(self, path: str, dry_run: bool = True) -> MigrationReport:
        """Run migration analysis and optionally apply replacements.

        Args:
            path: Path to analyze and optionally migrate.
            dry_run: If True, only report findings without modifying files.

        Returns:
            A MigrationReport with findings and any applied changes.

        .. note::
            Actual code modification is not yet implemented.
            TODO: Integrate ReplacementGenerator for automated code fixes.
        """
        report = self.analyze(path)

        if not dry_run:
            # TODO: Apply replacements using ReplacementGenerator
            pass

        return report

    def _scan_file(self, file_path: str) -> list[VulnerabilityFinding]:
        """Scan a single file for vulnerability patterns."""
        findings: list[VulnerabilityFinding] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return findings

        for line_number, line in enumerate(lines, start=1):
            for pattern_name, compiled in self._compiled_patterns.items():
                match = compiled.search(line)
                if match:
                    info = self.patterns[pattern_name]
                    findings.append(VulnerabilityFinding(
                        file_path=file_path,
                        line_number=line_number,
                        pattern_name=pattern_name,
                        risk_level=info["risk_level"],
                        description=info["description"],
                        replacement=info["replacement"],
                        matched_text=match.group(0),
                    ))

        return findings

    def _estimate_effort(self, vulnerabilities: list[VulnerabilityFinding]) -> str:
        """Estimate migration effort based on findings."""
        if not vulnerabilities:
            return "none"

        critical = sum(1 for v in vulnerabilities if v.risk_level == "CRITICAL")
        high = sum(1 for v in vulnerabilities if v.risk_level == "HIGH")
        total = len(vulnerabilities)

        if critical > 10 or total > 50:
            return "large (estimated 2-4 weeks)"
        elif critical > 5 or total > 20:
            return "medium (estimated 1-2 weeks)"
        elif critical > 0 or high > 5:
            return "small (estimated 2-5 days)"
        else:
            return "minimal (estimated 1-2 days)"
