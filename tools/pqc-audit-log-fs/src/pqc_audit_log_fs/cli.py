"""pqc-audit CLI."""

from __future__ import annotations

import json
import sys

import click

from pqc_audit_log_fs import __version__
from pqc_audit_log_fs.prover import InclusionProver
from pqc_audit_log_fs.reader import LogReader


@click.group()
@click.version_option(version=__version__, prog_name="pqc-audit")
def main() -> None:
    """pqc-audit - immutable AI inference audit log."""


@main.command()
@click.argument("log_dir", type=click.Path(exists=True))
def verify(log_dir: str) -> None:
    """Verify all segment signatures and the chain."""
    reader = LogReader(log_dir)
    ok, errors = reader.verify_chain()
    if ok:
        click.echo(f"[OK] all {len(reader.list_segments())} segments verify")
        sys.exit(0)
    else:
        for e in errors:
            click.echo(f"[FAIL] {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("log_dir", type=click.Path(exists=True))
@click.argument("segment_number", type=int)
@click.argument("event_id")
def prove(log_dir: str, segment_number: int, event_id: str) -> None:
    """Produce a Merkle inclusion proof for EVENT_ID in SEGMENT_NUMBER."""
    reader = LogReader(log_dir)
    prover = InclusionProver(reader)
    proof = prover.prove_event(segment_number, event_id)
    payload = proof.to_dict() if hasattr(proof, "to_dict") else proof.__dict__
    click.echo(json.dumps(payload, indent=2))


@main.command()
@click.argument("log_dir", type=click.Path(exists=True))
def info(log_dir: str) -> None:
    """Show info about a log directory."""
    reader = LogReader(log_dir)
    segments = reader.list_segments()
    click.echo(f"log_dir: {log_dir}")
    click.echo(f"segments: {len(segments)}")
    for n in segments:
        h = reader.read_header(n)
        prev = h.previous_segment_root[:16] + "..." if h.previous_segment_root else "<genesis>"
        click.echo(
            f"  segment {n:05d} events={h.event_count:>6} "
            f"root={h.merkle_root[:16]}... prev={prev} "
            f"sealed_at={h.sealed_at}"
        )


if __name__ == "__main__":
    main()
