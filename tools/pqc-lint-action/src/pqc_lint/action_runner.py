"""GitHub Action runner - invoked by action.yml composite step.

Reads configuration from PQC_LINT_* env vars (set by action.yml inputs)
and GITHUB_OUTPUT for workflow outputs.
"""

from __future__ import annotations

import os
import sys

from pqc_lint.findings import Severity
from pqc_lint.reporters import REPORTERS
from pqc_lint.scanner import DEFAULT_EXCLUDES, Scanner


def _set_output(name: str, value: str) -> None:
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")


def run() -> int:
    path = os.environ.get("PQC_LINT_PATH", ".")
    fail_on = os.environ.get("PQC_LINT_FAIL_ON", "high")
    output_format = os.environ.get("PQC_LINT_FORMAT", "github")
    output_file = os.environ.get("PQC_LINT_OUTPUT", "").strip()
    excludes_str = os.environ.get("PQC_LINT_EXCLUDE", "")
    languages_str = os.environ.get("PQC_LINT_LANGUAGES", "")

    lang_tuple = tuple(s.strip().lower() for s in languages_str.split(",") if s.strip())
    extra_excludes = tuple(s.strip() for s in excludes_str.split(",") if s.strip())
    excludes = DEFAULT_EXCLUDES + extra_excludes

    scanner = Scanner(languages=lang_tuple, excludes=excludes)
    report = scanner.scan_path(path)

    # Always emit GitHub annotations for inline PR feedback
    gh_output = REPORTERS["github"]().render(report)
    print(gh_output, end="")

    # Optional user-selected format to file or stdout
    if output_format != "github" or output_file:
        reporter_out = REPORTERS[output_format]().render(report)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(reporter_out)

    # SARIF is always produced if format == sarif OR if the user requested upload
    sarif_path = ""
    if output_format == "sarif":
        sarif_path = output_file or "pqc-lint.sarif"
        if not output_file:
            with open(sarif_path, "w", encoding="utf-8") as f:
                f.write(REPORTERS["sarif"]().render(report))
    else:
        # Always produce a default SARIF file so upload-sarif step can use it
        sarif_path = "pqc-lint.sarif"
        with open(sarif_path, "w", encoding="utf-8") as f:
            f.write(REPORTERS["sarif"]().render(report))

    counts = report.counts_by_severity()
    _set_output("total-findings", str(len(report.findings)))
    _set_output("critical", str(counts["critical"]))
    _set_output("high", str(counts["high"]))
    _set_output("medium", str(counts["medium"]))
    _set_output("low", str(counts["low"]))
    _set_output("sarif-path", sarif_path)

    threshold = Severity.from_str(fail_on)
    if report.has_failing(threshold):
        print(f"::error::pqc-lint: findings at or above '{fail_on}' severity detected. Failing the build.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
