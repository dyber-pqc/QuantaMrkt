"""Base pattern matcher interface."""

from __future__ import annotations

import re
from abc import ABC
from dataclasses import dataclass
from typing import Iterable, Pattern

from pqc_lint.findings import Finding
from pqc_lint.rules import Rule


@dataclass(frozen=True)
class PatternSpec:
    """A regex-based detection pattern bound to a rule."""
    rule_id: str
    regex: Pattern[str]
    description: str


class PatternMatcher(ABC):
    """Base class for per-language pattern matchers."""

    language: str = ""
    file_extensions: tuple[str, ...] = ()
    patterns: tuple[PatternSpec, ...] = ()

    def matches_file(self, path: str) -> bool:
        p = path.lower()
        return any(p.endswith(ext) for ext in self.file_extensions)

    def scan(self, file_path: str, content: str, rules: dict[str, Rule]) -> Iterable[Finding]:
        """Yield Findings for every pattern hit in `content`."""
        lines = content.split("\n")
        for spec in self.patterns:
            if spec.rule_id not in rules:
                continue
            rule = rules[spec.rule_id]
            for m in spec.regex.finditer(content):
                start = m.start()
                # Compute 1-based line and column
                prefix = content[:start]
                line_no = prefix.count("\n") + 1
                last_newline = prefix.rfind("\n")
                col_no = start - last_newline if last_newline >= 0 else start + 1

                snippet_line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                snippet = snippet_line.strip()[:200]

                yield Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=f"{rule.title}: {rule.message}",
                    file=file_path,
                    line=line_no,
                    column=col_no,
                    snippet=snippet,
                    suggestion=rule.suggestion,
                    cwe=rule.cwe,
                    language=self.language,
                )


def compile_patterns(specs: list[tuple[str, str]]) -> tuple[PatternSpec, ...]:
    """Helper: compile a list of (rule_id, regex_source) into PatternSpec tuples."""
    out: list[PatternSpec] = []
    for rule_id, pattern in specs:
        out.append(PatternSpec(
            rule_id=rule_id,
            regex=re.compile(pattern, re.MULTILINE),
            description=f"rule {rule_id}",
        ))
    return tuple(out)
