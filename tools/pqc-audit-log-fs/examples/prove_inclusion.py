"""prove_inclusion.py - generate + verify a Merkle inclusion proof.

Run::

    python examples/prove_inclusion.py
"""

from __future__ import annotations

import tempfile

from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs import (
    InclusionProver,
    InferenceEvent,
    LogAppender,
    LogReader,
    RotationPolicy,
)


def main() -> None:
    with tempfile.TemporaryDirectory() as log_dir:
        signer = AgentIdentity.create(name="demo-signer")
        appender = LogAppender(
            log_dir,
            signer,
            rotation=RotationPolicy(max_events_per_segment=1000),
        )

        target_event: InferenceEvent | None = None
        for i in range(50):
            event = InferenceEvent.create(
                model_did="did:pqaid:demo-model",
                model_version="1.0.0",
                input_bytes=f"in-{i}".encode(),
                output_bytes=f"out-{i}".encode(),
                decision_label="approve" if i % 2 == 0 else "deny",
            )
            appender.append(event)
            if i == 25:
                target_event = event
        appender.close()
        assert target_event is not None

        reader = LogReader(log_dir)
        prover = InclusionProver(reader)
        proof = prover.prove_event(1, target_event.event_id)
        print(f"built proof for event {target_event.event_id}")
        print(f"  tree_size = {proof.tree_size}")
        print(f"  siblings  = {len(proof.siblings)}")
        print(f"  root      = {proof.root[:16]}...")

        ok = InclusionProver.verify_proof(target_event, proof)
        print(f"[{'OK' if ok else 'FAIL'}] proof verifies: {ok}")


if __name__ == "__main__":
    main()
