"""Command-line interface for pqc-ebpf-attestation."""

from __future__ import annotations

import json
import sys

import click
from quantumshield.identity.agent import AgentIdentity

from pqc_ebpf_attestation import __version__
from pqc_ebpf_attestation.program import BPFProgram, BPFProgramMetadata, BPFProgramType
from pqc_ebpf_attestation.signer import BPFSigner, BPFVerifier, SignedBPFProgram


@click.group()
@click.version_option(version=__version__, prog_name="pqc-bpf")
def main() -> None:
    """pqc-bpf - sign and verify eBPF programs with ML-DSA."""


@main.command()
@click.argument("bpf_file", type=click.Path(exists=True))
@click.option("--name", required=True, help="Program name")
@click.option(
    "--type",
    "program_type",
    type=click.Choice([t.value for t in BPFProgramType]),
    default=BPFProgramType.KPROBE.value,
)
@click.option("--author", default="")
@click.option("--identity-name", default="bpf-signer", help="Name of the signing identity")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Write signed envelope JSON to file (default: <bpf_file>.sig.json)",
)
def sign(
    bpf_file: str,
    name: str,
    program_type: str,
    author: str,
    identity_name: str,
    output: str | None,
) -> None:
    """Sign an eBPF program file."""
    metadata = BPFProgramMetadata(
        name=name,
        program_type=BPFProgramType(program_type),
        author=author,
    )
    program = BPFProgram.from_file(metadata, bpf_file)

    identity = AgentIdentity.create(identity_name)
    signer = BPFSigner(identity)
    signed = signer.sign(program)

    out_path = output or f"{bpf_file}.sig.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(signed.to_dict(), f, indent=2)

    click.echo(f"Signed {bpf_file} -> {out_path}")
    click.echo(f"  signer_did: {signed.signer_did}")
    click.echo(f"  algorithm:  {signed.algorithm}")
    click.echo(f"  bytecode_hash: {signed.program.bytecode_hash}")


@main.command()
@click.argument("signed_json", type=click.Path(exists=True))
def verify(signed_json: str) -> None:
    """Verify a signed eBPF envelope."""
    with open(signed_json, encoding="utf-8") as f:
        data = json.load(f)
    signed = SignedBPFProgram.from_dict(data)
    result = BPFVerifier.verify(signed)
    if result.valid:
        click.echo(f"[OK] {signed.program.metadata.name} - signature VALID")
        click.echo(f"     signer_did:   {signed.signer_did}")
        click.echo(f"     program_type: {signed.program.metadata.program_type.value}")
        click.echo(f"     bytecode_hash: {signed.program.bytecode_hash}")
        sys.exit(0)
    else:
        click.echo(f"[FAIL] {signed.program.metadata.name} - {result.error}", err=True)
        sys.exit(1)


@main.command()
@click.argument("signed_json", type=click.Path(exists=True))
def info(signed_json: str) -> None:
    """Show metadata about a signed envelope."""
    with open(signed_json, encoding="utf-8") as f:
        data = json.load(f)
    signed = SignedBPFProgram.from_dict(data)
    click.echo(f"program name:  {signed.program.metadata.name}")
    click.echo(f"program type:  {signed.program.metadata.program_type.value}")
    click.echo(f"author:        {signed.program.metadata.author}")
    click.echo(f"description:   {signed.program.metadata.description}")
    click.echo(f"kernel min:    {signed.program.metadata.kernel_min}")
    click.echo(f"attach point:  {signed.program.metadata.attach_point}")
    click.echo(f"license:       {signed.program.metadata.license}")
    click.echo(f"bytecode hash: {signed.program.bytecode_hash}")
    click.echo(f"bytecode size: {signed.program.bytecode_size} bytes")
    click.echo(f"signer_did:    {signed.signer_did}")
    click.echo(f"algorithm:     {signed.algorithm}")
    click.echo(f"signed_at:     {signed.signed_at}")


if __name__ == "__main__":
    main()
