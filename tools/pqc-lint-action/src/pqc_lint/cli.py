"""Command-line interface for pqc-lint."""

from __future__ import annotations

import sys

import click

from pqc_lint import __version__
from pqc_lint.findings import Severity
from pqc_lint.reporters import REPORTERS
from pqc_lint.rules import RULES
from pqc_lint.scanner import DEFAULT_EXCLUDES, Scanner


@click.group()
@click.version_option(version=__version__, prog_name="pqc-lint")
def main() -> None:
    """PQC Lint - find classical cryptography and suggest PQC replacements."""


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "sarif", "github"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--output", "-o", "output_file",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="high",
    help="Exit with non-zero status if any finding is >= this severity.",
)
@click.option(
    "--languages", "-l",
    default="",
    help="Comma-separated languages to scan (python,javascript,go,rust,java,c). Empty=all.",
)
@click.option(
    "--exclude",
    default="",
    help="Comma-separated glob patterns to exclude (in addition to defaults).",
)
def scan(
    path: str,
    output_format: str,
    output_file: str | None,
    fail_on: str,
    languages: str,
    exclude: str,
) -> None:
    """Scan PATH for classical cryptography usage."""
    lang_tuple = tuple(
        s.strip().lower() for s in languages.split(",") if s.strip()
    )
    extra_excludes = tuple(s.strip() for s in exclude.split(",") if s.strip())
    excludes = DEFAULT_EXCLUDES + extra_excludes

    scanner = Scanner(languages=lang_tuple, excludes=excludes)
    report = scanner.scan_path(path)

    reporter_cls = REPORTERS[output_format]
    output = reporter_cls().render(report)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)
        click.echo(f"Wrote {output_format} report to {output_file}")
    else:
        click.echo(output, nl=False)

    # exit code based on fail-on
    threshold = Severity.from_str(fail_on)
    if report.has_failing(threshold):
        sys.exit(1)


@main.command()
def rules() -> None:
    """List all rules."""
    click.echo(f"pqc-lint rules ({len(RULES)})\n")
    for r in RULES:
        click.echo(f"  {r.id}  [{r.severity.value.upper():8}]  {r.title}")
        click.echo(f"          primitive: {r.classical_primitive}")
        click.echo(f"          languages: {', '.join(r.languages)}")
        if r.cwe:
            click.echo(f"          cwe:       {r.cwe}")
        click.echo()


if __name__ == "__main__":
    main()
