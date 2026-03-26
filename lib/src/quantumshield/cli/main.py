"""QuantumShield CLI - Post-quantum cryptography toolkit for AI systems.

Provides both grouped sub-commands (``agent``, ``migrate``, ``registry``)
and top-level Ollama-style commands (``login``, ``push``, ``pull``,
``verify``, ``models``, ``search``).
"""

from __future__ import annotations

import hashlib
import json
import sys
import time

import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# GitHub OAuth Device Flow client ID
_GITHUB_CLIENT_ID = "Ov23liuaDLn9Xtgh2uCO"


# =====================================================================
# Root group
# =====================================================================

@click.group()
@click.version_option(version="0.1.0", prog_name="quantumshield")
def cli() -> None:
    """QuantumShield - Post-quantum cryptography toolkit for AI systems."""


# =====================================================================
# Top-level Ollama-style commands
# =====================================================================

@cli.command("login")
def login_cmd() -> None:
    """Authenticate with GitHub (Device Flow)."""
    from quantumshield.cli.config import set_auth_token

    console.print("[bold]Authenticating with GitHub...[/bold]\n")

    # Step 1 - request device + user codes
    resp = httpx.post(
        "https://github.com/login/device/code",
        data={"client_id": _GITHUB_CLIENT_ID, "scope": "read:user"},
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if resp.status_code != 200:
        console.print(f"[red]Failed to start device flow: {resp.text}[/red]")
        sys.exit(1)

    payload = resp.json()
    device_code = payload["device_code"]
    user_code = payload["user_code"]
    verification_uri = payload["verification_uri"]
    interval = payload.get("interval", 5)
    expires_in = payload.get("expires_in", 900)

    console.print(Panel.fit(
        f"Go to [bold cyan]{verification_uri}[/bold cyan]\n\n"
        f"and enter code: [bold yellow]{user_code}[/bold yellow]",
        title="GitHub Device Activation",
        border_style="cyan",
    ))

    # Step 2 - poll for the access token
    deadline = time.time() + expires_in
    with console.status("[bold blue]Waiting for authorization..."):
        while time.time() < deadline:
            time.sleep(interval)
            token_resp = httpx.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": _GITHUB_CLIENT_ID,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json"},
                timeout=15,
            )
            data = token_resp.json()
            error = data.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            if error:
                console.print(f"[red]Auth error: {error} - {data.get('error_description', '')}[/red]")
                sys.exit(1)
            # Success
            access_token = data["access_token"]
            set_auth_token(access_token)
            console.print("\n[bold green]Successfully logged in![/bold green]")

            # Fetch username for friendly display
            try:
                user_resp = httpx.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10,
                )
                if user_resp.status_code == 200:
                    username = user_resp.json().get("login", "unknown")
                    console.print(f"Welcome, [bold]{username}[/bold]!")
            except Exception:
                pass
            return

    console.print("[red]Authentication timed out. Please try again.[/red]")
    sys.exit(1)


@cli.command("push")
@click.argument("path")
@click.option("--name", "-n", required=True, help="Model slug (org/model-name).")
def push_cmd(path: str, name: str) -> None:
    """Push a model directory to the registry."""
    from quantumshield.cli.config import is_logged_in
    from quantumshield.core.keystore import (
        get_default_identity,
        save_identity,
        set_default_identity,
    )
    from quantumshield.identity.agent import AgentIdentity
    from quantumshield.registry.manifest import ModelManifest
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    # 1. Auth check
    if not is_logged_in():
        console.print("[red]Not logged in. Run [bold]quantumshield login[/bold] first.[/red]")
        sys.exit(1)

    # 2. Ensure default identity exists
    identity_info = get_default_identity()
    if identity_info is None:
        console.print("[yellow]No default identity found. Creating one...[/yellow]")
        agent = AgentIdentity.create("default")
        save_identity("default", agent.signing_keypair, agent.did)
        set_default_identity("default")
        keypair, did = agent.signing_keypair, agent.did
        console.print(f"[green]Created identity:[/green] {did}")
    else:
        keypair, did = identity_info

    # 3. Build manifest
    with console.status("[bold blue]Hashing model files..."):
        manifest = ModelManifest.from_model(path)

    console.print(f"[green]Found {len(manifest.files)} files.[/green]")

    # 4. Sign manifest
    manifest_hash = hashlib.sha3_256(manifest._canonical_bytes()).hexdigest()
    manifest.sign(keypair, signer_did=did)
    console.print(f"[green]Manifest signed by {did}[/green]")

    # 5. Push
    reg = ShieldRegistry()
    with console.status("[bold blue]Pushing to registry..."):
        try:
            # Try to create the model first (idempotent)
            try:
                reg.create_model(name)
            except RegistryError:
                pass  # model may already exist
            reg.push(manifest, name)
        except RegistryError as exc:
            console.print(f"[red]Push failed: {exc}[/red]")
            sys.exit(1)

    console.print(Panel.fit(
        f"[bold green]Model pushed successfully![/bold green]\n\n"
        f"[bold]Name:[/bold]   {name}\n"
        f"[bold]Files:[/bold]  {len(manifest.files)}\n"
        f"[bold]Hash:[/bold]   {manifest_hash[:16]}...\n"
        f"[bold]Signer:[/bold] {did}\n"
        f"[bold]URL:[/bold]    https://quantamrkt.com/{name}",
        title="Push Complete",
        border_style="green",
    ))


@cli.command("pull")
@click.argument("name")
def pull_cmd(name: str) -> None:
    """Pull model info from the registry."""
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    reg = ShieldRegistry()
    with console.status(f"[bold blue]Fetching {name}..."):
        try:
            data = reg.pull(name)
        except RegistryError as exc:
            console.print(f"[red]Pull failed: {exc}[/red]")
            sys.exit(1)

    # Display model info
    model = data.get("model", data.get("metadata", {}))
    console.print(Panel.fit(
        f"[bold]{model.get('name', name)}[/bold]\n"
        f"Version: {model.get('version', 'n/a')}\n"
        f"Framework: {model.get('framework', 'n/a')}\n"
        f"Description: {model.get('description', '')}",
        title=f"Model: {name}",
        border_style="blue",
    ))

    # File listing
    files = data.get("files", [])
    if files:
        table = Table(title="Files")
        table.add_column("Path", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("SHA3-256", style="dim")
        for f in files:
            size = f.get("size", 0)
            size_str = _human_size(size)
            table.add_row(f.get("path", "?"), size_str, f.get("hash_value", "")[:16] + "...")
        console.print(table)

    # Signatures
    sigs = data.get("signatures", [])
    if sigs:
        table = Table(title="Signatures")
        table.add_column("Signer", style="cyan")
        table.add_column("Algorithm")
        table.add_column("Signed At")
        table.add_column("Type")
        for s in sigs:
            table.add_row(
                s.get("signer", "?"),
                s.get("algorithm", "?"),
                s.get("signed_at", "?"),
                s.get("attestation_type", "?"),
            )
        console.print(table)

    source_url = data.get("source_url") or data.get("url")
    if source_url:
        console.print(f"\nFiles are hosted at: [link={source_url}]{source_url}[/link]")


@cli.command("verify")
@click.argument("name")
def verify_cmd(name: str) -> None:
    """Verify a model's signatures."""
    from quantumshield.core.keys import has_pqc  # noqa: F811
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    reg = ShieldRegistry()
    with console.status(f"[bold blue]Verifying {name}..."):
        try:
            data = reg.verify(name)
        except RegistryError as exc:
            console.print(f"[red]Verification failed: {exc}[/red]")
            sys.exit(1)

    verified = data.get("verified", False)
    sigs = data.get("signatures", [])

    if verified:
        console.print(Panel.fit(
            f"[bold green]VERIFIED[/bold green]  {name}\n\n"
            f"All {len(sigs)} signature(s) are valid.",
            title="Verification Result",
            border_style="green",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]FAILED[/bold red]  {name}\n\n"
            f"Signature verification failed.",
            title="Verification Result",
            border_style="red",
        ))

    if sigs:
        table = Table(title="Signature Details")
        table.add_column("Signer DID", style="cyan")
        table.add_column("Algorithm")
        table.add_column("Status")
        for s in sigs:
            status = s.get("status", "unknown")
            style = "green" if status == "valid" else "red"
            table.add_row(
                s.get("signer", "?"),
                s.get("algorithm", "?"),
                f"[{style}]{status}[/{style}]",
            )
        console.print(table)

    if has_pqc():
        console.print("[dim]Local PQC verification: available (liboqs detected)[/dim]")
    else:
        console.print("[dim]Local PQC verification: unavailable (install liboqs for local verify)[/dim]")

    if not verified:
        sys.exit(1)


@cli.command("models")
def models_cmd() -> None:
    """List your models on the registry."""
    from quantumshield.cli.config import is_logged_in
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    if not is_logged_in():
        console.print("[red]Not logged in. Run [bold]quantumshield login[/bold] first.[/red]")
        sys.exit(1)

    reg = ShieldRegistry()
    with console.status("[bold blue]Fetching your models..."):
        try:
            models = reg.list_user_models()
        except RegistryError as exc:
            console.print(f"[red]Failed: {exc}[/red]")
            sys.exit(1)

    if not models:
        console.print("[yellow]No models found. Push one with [bold]quantumshield push[/bold].[/yellow]")
        return

    table = Table(title="Your Models")
    table.add_column("Name", style="bold cyan")
    table.add_column("Version")
    table.add_column("Files", justify="right")
    table.add_column("Signatures", justify="right")
    table.add_column("Updated")
    for m in models:
        table.add_row(
            m.get("slug", m.get("name", "?")),
            m.get("version", "?"),
            str(m.get("file_count", m.get("files", "?"))),
            str(m.get("signature_count", m.get("signatures", "?"))),
            m.get("updated_at", m.get("created_at", "?")),
        )
    console.print(table)


@cli.command("search")
@click.argument("query")
def search_cmd(query: str) -> None:
    """Search for models on the registry."""
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    reg = ShieldRegistry()
    with console.status(f"[bold blue]Searching for '{query}'..."):
        try:
            results = reg.search(query)
        except RegistryError as exc:
            console.print(f"[red]Search failed: {exc}[/red]")
            sys.exit(1)

    if not results:
        console.print(f"[yellow]No models found matching '{query}'.[/yellow]")
        return

    table = Table(title=f"Search Results: {query}")
    table.add_column("Name", style="bold cyan")
    table.add_column("Description", max_width=50)
    table.add_column("Author")
    table.add_column("Signatures", justify="right")
    for m in results:
        table.add_row(
            m.get("slug", m.get("name", "?")),
            m.get("description", "")[:50],
            m.get("author", "?"),
            str(m.get("signature_count", m.get("signatures", "?"))),
        )
    console.print(table)


# =====================================================================
# Agent sub-group
# =====================================================================

@cli.group()
def agent() -> None:
    """Manage agent identities."""


@agent.command("create")
@click.argument("name")
@click.option(
    "--algorithm", "-a",
    type=click.Choice(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
    default="ML-DSA-65",
    help="Signature algorithm to use.",
)
@click.option(
    "--capabilities", "-c",
    multiple=True,
    help="Agent capabilities (can specify multiple times).",
)
@click.option("--set-default", is_flag=True, help="Set this identity as the default.")
def agent_create(name: str, algorithm: str, capabilities: tuple[str, ...], set_default: bool) -> None:
    """Create a new agent identity and save it to the local keystore."""
    from quantumshield.core.algorithms import SignatureAlgorithm
    from quantumshield.core.keystore import save_identity, set_default_identity
    from quantumshield.identity.agent import AgentIdentity

    algo = SignatureAlgorithm(algorithm)
    caps = list(capabilities) if capabilities else ["sign", "verify"]
    identity = AgentIdentity.create(name, capabilities=caps, algorithm=algo)

    # Persist
    path = save_identity(name, identity.signing_keypair, identity.did)
    if set_default:
        set_default_identity(name)

    console.print(Panel.fit(
        f"[bold green]Agent created successfully[/bold green]\n\n"
        f"[bold]Name:[/bold]      {identity.name}\n"
        f"[bold]DID:[/bold]       {identity.did}\n"
        f"[bold]Algorithm:[/bold] {identity.signing_keypair.algorithm.value}\n"
        f"[bold]Capabilities:[/bold] {', '.join(identity.capabilities)}\n"
        f"[bold]Stored at:[/bold] {path}\n"
        f"[bold]Default:[/bold]   {'yes' if set_default else 'no'}",
        title="QuantumShield Agent",
        border_style="green",
    ))

    console.print("\n[dim]Public identity JSON:[/dim]")
    console.print(identity.export())


@agent.command("list")
def agent_list() -> None:
    """List all saved agent identities."""
    from quantumshield.core.keystore import list_identities, load_config

    identities = list_identities()
    default_name = load_config("default_identity")

    if not identities:
        console.print("[yellow]No identities found. Create one with [bold]quantumshield agent create[/bold].[/yellow]")
        return

    table = Table(title="Saved Identities")
    table.add_column("Name", style="bold cyan")
    table.add_column("DID", style="dim")
    table.add_column("Algorithm")
    table.add_column("Default", justify="center")
    for ident in identities:
        is_default = "(*)" if ident["name"] == default_name else ""
        table.add_row(
            ident["name"],
            ident["did"][:40] + "...",
            ident["algorithm"],
            is_default,
        )
    console.print(table)


@agent.command("sign")
@click.option("--action", "-a", required=True, help="Action to sign.")
@click.option("--target", "-t", required=True, help="Target of the action.")
@click.option("--identity", "-i", default=None, help="Identity name to use (default: default identity).")
def agent_sign(action: str, target: str, identity: str | None) -> None:
    """Sign an action credential."""
    from quantumshield.core.keystore import get_default_identity, load_identity
    from quantumshield.identity.agent import AgentIdentity

    if identity:
        try:
            keypair, did = load_identity(identity)
        except FileNotFoundError:
            console.print(f"[red]Identity '{identity}' not found.[/red]")
            sys.exit(1)
    else:
        result = get_default_identity()
        if result is None:
            console.print(
                "[yellow]No default identity. Creating ephemeral agent...[/yellow]"
            )
            agent = AgentIdentity.create("ephemeral-signer")
            keypair, did = agent.signing_keypair, agent.did
        else:
            keypair, did = result

    # Build a minimal AgentIdentity to call sign_action
    agent_obj = AgentIdentity(
        did=did,
        name=identity or "default",
        signing_keypair=keypair,
    )
    credential = agent_obj.sign_action(action, target)

    console.print(Panel.fit(
        f"[bold green]Action signed[/bold green]\n\n"
        f"[bold]Signer:[/bold]    {credential.signer_did}\n"
        f"[bold]Action:[/bold]    {credential.action}\n"
        f"[bold]Target:[/bold]    {credential.target}\n"
        f"[bold]Signed at:[/bold] {credential.signed_at.isoformat()}\n"
        f"[bold]Algorithm:[/bold] {credential.algorithm.value}\n"
        f"[bold]Signature:[/bold] {credential.signature.hex()[:32]}...",
        title="Action Credential",
        border_style="blue",
    ))


# =====================================================================
# Migrate sub-group
# =====================================================================

@cli.group()
def migrate() -> None:
    """Analyze and migrate cryptographic code."""


@migrate.command("analyze")
@click.argument("path")
def migrate_analyze(path: str) -> None:
    """Analyze a codebase for quantum-vulnerable cryptography."""
    from quantumshield.migrator.analyzer import MigrationAgent

    with console.status("[bold blue]Scanning for quantum-vulnerable cryptography..."):
        migration_agent = MigrationAgent()
        report = migration_agent.analyze(path)

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

    risk_table = Table(title="Risk Summary")
    risk_table.add_column("Level", style="bold")
    risk_table.add_column("Count", justify="right")
    risk_table.add_row("[red]CRITICAL[/red]", str(report.critical_count))
    risk_table.add_row("[yellow]HIGH[/yellow]", str(report.high_count))
    risk_table.add_row("[blue]MEDIUM[/blue]", str(report.medium_count))
    risk_table.add_row("[dim]LOW[/dim]", str(report.low_count))
    console.print(risk_table)

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
        migration_agent = MigrationAgent()
        report = migration_agent.migrate(path, dry_run=dry_run)

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


# =====================================================================
# Registry sub-group (kept for backwards-compat)
# =====================================================================

@cli.group()
def registry() -> None:
    """Sign, push, and verify model manifests."""


@registry.command("sign")
@click.argument("path")
@click.option("--output", "-o", default=None, help="Output manifest path.")
@click.option("--identity", "-i", default=None, help="Identity name to use.")
def registry_sign(path: str, output: str | None, identity: str | None) -> None:
    """Create and sign a model manifest."""
    from quantumshield.core.keystore import get_default_identity, load_identity
    from quantumshield.identity.agent import AgentIdentity
    from quantumshield.registry.manifest import ModelManifest

    with console.status("[bold blue]Hashing model files..."):
        manifest = ModelManifest.from_model(path)

    console.print(f"[green]Found {len(manifest.files)} files to include in manifest.[/green]")

    # Resolve signing identity
    if identity:
        try:
            keypair, did = load_identity(identity)
        except FileNotFoundError:
            console.print(f"[red]Identity '{identity}' not found.[/red]")
            sys.exit(1)
    else:
        result = get_default_identity()
        if result is not None:
            keypair, did = result
        else:
            console.print("[yellow]No stored identity. Creating ephemeral signer...[/yellow]")
            agent = AgentIdentity.create("manifest-signer")
            keypair, did = agent.signing_keypair, agent.did

    manifest.sign(keypair, signer_did=did)

    output_path = output or "manifest.json"
    manifest.save(output_path)
    console.print(Panel.fit(
        f"[bold green]Manifest signed and saved[/bold green]\n\n"
        f"[bold]Files:[/bold]  {len(manifest.files)}\n"
        f"[bold]Signer:[/bold] {did}\n"
        f"[bold]Output:[/bold] {output_path}",
        title="Model Manifest",
        border_style="green",
    ))


@registry.command("push")
@click.argument("namespace")
@click.option("--manifest", "-m", default="manifest.json", help="Path to manifest file.")
def registry_push(namespace: str, manifest: str) -> None:
    """Push a signed manifest to the registry."""
    from quantumshield.registry.manifest import ModelManifest
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    with open(manifest, "r") as f:
        data = json.load(f)
    m = ModelManifest.model_validate(data)

    reg = ShieldRegistry()
    try:
        reg.push(m, namespace)
        console.print(f"[green]Manifest pushed to {namespace}.[/green]")
    except RegistryError as exc:
        console.print(f"[red]Push failed: {exc}[/red]")
        sys.exit(1)


@registry.command("verify")
@click.argument("namespace")
def registry_verify(namespace: str) -> None:
    """Verify a manifest's signatures in the registry."""
    from quantumshield.registry.signing import RegistryError, ShieldRegistry

    reg = ShieldRegistry()
    try:
        result = reg.verify(namespace)
        verified = result.get("verified", False)
        if verified:
            console.print(f"[green]Manifest {namespace} verified successfully.[/green]")
        else:
            console.print(f"[red]Manifest {namespace} verification failed.[/red]")
            sys.exit(1)
    except RegistryError as exc:
        console.print(f"[red]Verification error: {exc}[/red]")
        sys.exit(1)


# =====================================================================
# Utilities
# =====================================================================

def _human_size(nbytes: int) -> str:
    """Format bytes as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes //= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} PB"


if __name__ == "__main__":
    cli()
