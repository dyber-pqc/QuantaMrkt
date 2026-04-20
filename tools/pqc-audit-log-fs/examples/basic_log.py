"""basic_log.py - write 30 events with rotation, then verify the chain.

Run::

    python examples/basic_log.py
"""

from __future__ import annotations

import tempfile

from quantumshield.identity.agent import AgentIdentity

from pqc_audit_log_fs import (
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
            rotation=RotationPolicy(max_events_per_segment=10),
        )

        for i in range(30):
            event = InferenceEvent.create(
                model_did="did:pqaid:demo-model",
                model_version="1.0.0",
                input_bytes=f"input-{i}".encode(),
                output_bytes=f"output-{i}".encode(),
                decision_type="classification",
                decision_label="approve" if i % 2 == 0 else "deny",
                actor_did="did:pqaid:demo-user",
                session_id=f"sess-{i // 5}",
            )
            appender.append(event)
        appender.close()

        reader = LogReader(log_dir)
        segments = reader.list_segments()
        print(f"wrote {len(segments)} sealed segments")
        for n in segments:
            header = reader.read_header(n)
            print(
                f"  segment {n:05d} "
                f"events={header.event_count} "
                f"root={header.merkle_root[:16]}..."
            )

        ok, errors = reader.verify_chain()
        if ok:
            print(f"[OK] chain verifies across {len(segments)} segments")
        else:
            print("[FAIL] chain verification failed:")
            for e in errors:
                print(f"  - {e}")


if __name__ == "__main__":
    main()
