"""QuantumShield CLI - Post-quantum cryptography toolkit for AI systems."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="quantumshield")
def cli() -> None:
    """QuantumShield - Post-quantum cryptography toolkit for AI systems."""
    pass


# ---------------------------------------------------------------------------
# Agent commands
# ---------------------------------------------------------------------------


@cli.group()
def agent() -> None:
    """Manage agent identities."""
    pass


@agent.command("create")
@click.argument("name")
@click.option(
    "--algorithm",
    "-a",
    type=click.Choice(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
    default="ML-DSA-65",
    help="Signature algorithm to use.",
)
@click.option(
    "--capabilities",
    "-c",
    multiple=True,
    help="Agent capabilities (can specify multiple times).",
)
def agent_create(name: str, algorithm: str, capabilities: tuple[str, ...]) -> None:
    """Create a new agent identity."""
    from quantumshield.core.algorithms import SignatureAlgorithm
    from quantumshield.identity.agent import AgentIdentity

    algo = SignatureAlgorithm(algorithm)
    caps = list(capabilities) if capabilities else ["sign", "verify"]
    identity = AgentIdentity.create(name, capabilities=caps, algorithm=algo)

    console.print(Panel.fit(
        f"[bold green]Agent created successfully[/bold green]\n\n"
        f"[bold]Name:[/bold] {identity.name}\n"
        f"[bold]DID:[/bold]  {identity.did}\n"
        f"[bold]Algorithm:[/bold] {identity.signing_keypair.algorithm.value}\n"
        f"[bold]Capabilities:[/bold] {', '.join(identity.capabilities)}\n"
        f"[bold]Created:[/bold] {identity.created_at.isoformat()}",
        title="QuantumShield Agent",
        border_style="green",
    ))

    # Output public identity JSON
    console.print("\n[dim]Public identity JSON:[/dim]")
    console.print(identity.export())


@agent.command("sign")
@click.option("--action", "-a", required=True, help="Action to sign.")
@click.option("--target", "-t", required=True, help="Target of the action.")
def agent_sign(action: str, target: str) -> None:
    """Sign an action credential (requires stored identity)."""
    # TODO: Load stored identity from config
    from quantumshield.identity.agent import AgentIdentity

    console.print("[yellow]Creating ephemeral agent for signing (no stored identity found)...[/yellow]")
    identity = AgentIdentity.create("ephemeral-signer")
    credential = identity.sign_action(action, target)

    console.print(Panel.fit(
        f"[bold green]Action signed[/bold green]\n\n"
        f"[bold]Signer:[/bold] {credential.signer_did}\n"
        f"[bold]Action:[/bold] {credential.action}\n"
        f"[bold]Target:[/bold] {credential.target}\n"
        f"[bold]Signed at:[/bold] {credential.signed_at.isoformat()}\n"
        f"[bold]Algorithm:[/bold] {credential.algorithm.value}\n"
        f"[bold]Signature:[/bold] {credential.signature.hex()[:32]}...",
        title="Action Credential",
        border_style="blue",
    ))


# ---------------------------------------------------------------------------
# Migrate commands
# ---------------------------------------------------------------------------


@cli.group()
def migrate() -> None:
    """Analyze and migrate cryptographic code."""
    pass


@migrate.command("analyze")
@click.argument("path")
def migrate_analyze(path: str) -> None:
    """Analyze a codebase for quantum-vulnerable cryptography."""
    from quantumshield.migrator.analyzer import MigrationAgent

    with console.status("[bold blue]Scanning for quantum-vulnerable cryptography..."):
        agent = MigrationAgent()
        report = agent.analyze(path)

    # Summary panel
    console.print(Panel.fit(
        f"[bold]Files scanned:[/bold] {report.files_scanned}\n"
        f"[bold]Files with crypto:[/bold] {report.files_with_crypto}\n"
        f"[bold]Total vulnerabilities:[/bold] {len(report.vulnerabilities)}\n"
        f"[bold]Effort estimate:[/bold] {report.effort_estimate}",
        title="Migration Analysis Report",
        border_style="blue",
    ))

    if not report.vulnerabilities:
        console.print("[green]No quantum-vulnerable cryptography detected.[/green]")
        return

    # Risk summary
    risk_table = Table(title="Risk Summary")
    risk_table.add_column("Level", style="bold")
    risk_table.add_column("Count", justify="right")
    risk_table.add_row("[red]CRITICAL[/red]", str(report.critical_count))
    risk_table.add_row("[yellow]HIGH[/yellow]", str(report.high_count))
    risk_table.add_row("[blue]MEDIUM[/blue]", str(report.medium_count))
    risk_table.add_row("[dim]LOW[/dim]", str(report.low_count))
    console.print(risk_table)

    # Detailed findings
    findings_table = Table(title="Vulnerability Findings", show_lines=True)
    findings_table.add_column("File", style="cyan", max_width=40)
    findings_table.add_column("Line", justify="right")
    findings_table.add_column("Pattern", style="bold")
    findings_table.add_column("Risk", justify="center")
    findings_table.add_column("Description", max_width=50)

    risk_styles = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[yellow]HIGH[/yellow]",
        "MEDIUM": "[blue]MEDIUM[/blue]",
        "LOW": "[dim]LOW[/dim]",
    }

    for finding in report.vulnerabilities:
        findings_table.add_row(
            finding.file_path,
            str(finding.line_number),
            finding.pattern_name,
            risk_styles.get(finding.risk_level, finding.risk_level),
            finding.description[:80],
        )

    console.print(findings_table)


@migrate.command("run")
@click.argument("path")
@click.option("--validate-kat", is_flag=True, help="Run Known Answer Tests after migration.")
@click.option("--dry-run", is_flag=True, default=True, help="Only report, don't modify files.")
def migrate_run(path: str, validate_kat: bool, dry_run: bool) -> None:
    """Run migration on a codebase."""
    from quantumshield.migrator.analyzer import MigrationAgent

    with console.status("[bold blue]Running migration analysis..."):
        agent = MigrationAgent()
        report = agent.migrate(path, dry_run=dry_run)

    console.print(Panel.fit(
        f"[bold]Mode:[/bold] {'Dry run' if dry_run else 'Live migration'}\n"
        f"[bold]Files scanned:[/bold] {report.files_scanned}\n"
        f"[bold]Vulnerabilities:[/bold] {len(report.vulnerabilities)}\n"
        f"[bold]Effort:[/bold] {report.effort_estimate}",
        title="Migration Run",
        border_style="yellow" if dry_run else "green",
    ))

    if validate_kat:
        console.print("[yellow]KAT validation requested (not yet implemented).[/yellow]")


# ---------------------------------------------------------------------------
# Registry commands
# ---------------------------------------------------------------------------


@cli.group()
def registry() -> None:
    """Sign, push, and verify model manifests."""
    pass


@registry.command("sign")
@click.argument("path")
@click.option("--output", "-o", default=None, help="Output manifest path.")
def registry_sign(path: str, output: str | None) -> None:
    """Create and sign a model manifest."""
    from quantumshield.identity.agent import AgentIdentity
    from quantumshield.registry.manifest import ModelManifest

    with console.status("[bold blue]Hashing model files..."):
        manifest = ModelManifest.from_model(path)

    console.print(f"[green]Found {len(manifest.files)} files to include in manifest.[/green]")

    # Create ephemeral agent for signing
    # TODO: Use stored identity
    identity = AgentIdentity.create("manifest-signer")
    manifest.sign(identity.signing_keypair, signer_did=identity.did)

    output_path = output or "manifest.json"
    manifest.save(output_path)
    console.print(Panel.fit(
        f"[bold green]Manifest signed and saved[/bold green]\n\n"
        f"[bold]Files:[/bold] {len(manifest.files)}\n"
        f"[bold]Signer:[/bold] {identity.did}\n"
        f"[bold]Output:[/bold] {output_path}",
        title="Model Manifest",
        border_style="green",
    ))


@registry.command("push")
@click.argument("namespace")
@click.option("--manifest", "-m", default="manifest.json", help="Path to manifest file.")
@click.option("--api-url", default="https://registry.quantumshield.dev", help="Registry URL.")
def registry_push(namespace: str, manifest: str, api_url: str) -> None:
    """Push a signed manifest to the registry."""
    from quantumshield.registry.manifest import ModelManifest
    from quantumshield.registry.signing import ShieldRegistry

    with open(manifest, "r") as f:
        data = json.load(f)
    m = ModelManifest.model_validate(data)

    reg = ShieldRegistry(api_url=api_url)
    result = reg.push(m, namespace)
    console.print(f"[yellow]Registry push: {result['message']}[/yellow]")


@registry.command("verify")
@click.argument("namespace")
@click.option("--api-url", default="https://registry.quantumshield.dev", help="Registry URL.")
def registry_verify(namespace: str, api_url: str) -> None:
    """Verify a manifest's signatures in the registry."""
    from quantumshield.registry.signing import ShieldRegistry

    reg = ShieldRegistry(api_url=api_url)
    try:
        result = reg.verify(namespace)
        if result:
            console.print(f"[green]Manifest {namespace} verified successfully.[/green]")
        else:
            console.print(f"[red]Manifest {namespace} verification failed.[/red]")
            sys.exit(1)
    except NotImplementedError as e:
        console.print(f"[yellow]{e}[/yellow]")


if __name__ == "__main__":
    cli()
