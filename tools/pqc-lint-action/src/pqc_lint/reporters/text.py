"""Plain-text reporter for terminal output."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table

from pqc_lint.findings import ScanReport, Severity
from pqc_lint.reporters.base import Reporter

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class TextReporter(Reporter):
    format_name = "text"

    def render(self, report: ScanReport) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, width=120)

        counts = report.counts_by_severity()
        total = len(report.findings)

        console.print()
        console.print("[bold]PQC Lint Scan Report[/bold]")
        console.print(f"Root: {report.scan_root}")
        console.print(
            f"Files scanned: {report.files_scanned}  "
            f"skipped: {report.files_skipped}  "
            f"duration: {report.duration_ms}ms"
        )
        console.print()
        console.print(
            f"[bold]Summary[/bold]: {total} findings  "
            f"[bold red]{counts['critical']} critical[/bold red]  "
            f"[red]{counts['high']} high[/red]  "
            f"[yellow]{counts['medium']} medium[/yellow]  "
            f"[cyan]{counts['low']} low[/cyan]"
        )
        console.print()

        if not report.findings:
            console.print("[green]No classical crypto detected. Looks PQC-clean.[/green]")
            return buf.getvalue()

        # Group findings by file
        by_file: dict[str, list] = {}
        for f in report.findings:
            by_file.setdefault(f.file, []).append(f)

        for path in sorted(by_file):
            console.print(f"[bold]{path}[/bold]")
            table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
            table.add_column("Line", justify="right", style="dim")
            table.add_column("Severity")
            table.add_column("Rule")
            table.add_column("Message")
            for finding in sorted(by_file[path], key=lambda x: x.line):
                style = _SEVERITY_STYLE[finding.severity]
                table.add_row(
                    str(finding.line),
                    f"[{style}]{finding.severity.value.upper()}[/{style}]",
                    finding.rule_id,
                    finding.message.split(":")[0],
                )
            console.print(table)
            for finding in sorted(by_file[path], key=lambda x: x.line):
                if finding.snippet:
                    console.print(
                        f"  [dim]{finding.line}[/dim]  "
                        f"[dim cyan]{finding.snippet}[/dim cyan]"
                    )
                if finding.suggestion:
                    console.print(f"     [dim]->[/dim] {finding.suggestion}")
            console.print()

        return buf.getvalue()
