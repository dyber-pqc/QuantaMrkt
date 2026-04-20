"""tamper_detection.py - show that LogReader flags any mutation to a sealed log.

Run::

    python examples/tamper_detection.py
"""

from __future__ import annotations

import json
import os
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
            rotation=RotationPolicy(max_events_per_segment=1000),
        )

        for i in range(20):
            event = InferenceEvent.create(
                model_did="did:pqaid:demo-model",
                model_version="1.0.0",
                input_bytes=f"in-{i}".encode(),
                output_bytes=f"out-{i}".encode(),
                decision_label="approve",
            )
            appender.append(event)
        appender.close()

        # Mutate one line in the sealed segment
        jsonl = os.path.join(log_dir, "segment-00001.log")
        with open(jsonl, "r", encoding="utf-8") as f:
            lines = f.readlines()
        third = json.loads(lines[2])
        third["decision_label"] = "deny"    # forger swaps the outcome
        lines[2] = json.dumps(third, separators=(",", ":")) + "\n"
        with open(jsonl, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print("[tamper] mutated line 3 of segment-00001.log")

        reader = LogReader(log_dir)
        ok, errors = reader.verify_chain()
        if ok:
            print("[FAIL] tamper was NOT detected")
        else:
            print(f"[OK] tamper detected across {len(errors)} error(s):")
            for e in errors:
                print(f"  - {e}")


if __name__ == "__main__":
    main()
