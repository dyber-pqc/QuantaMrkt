"""Legacy Monitor -- SUSPENDED. Demonstrates the revocation flow."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity

from pqc_lint import Scanner
from pqc_audit_log_fs import InferenceEvent, LogAppender, RotationPolicy


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> tuple[AgentIdentity, str]:
    data = json.loads(IDENTITY_FILE.read_text())
    agent = AgentIdentity.create(
        data["name"],
        capabilities=data["capabilities"],
        algorithm=SignatureAlgorithm.ML_DSA_44,
    )
    return agent, data.get("status", "active")


def scan_legacy(agent: AgentIdentity, root: str) -> int:
    """Count quantum-vulnerable findings in a legacy codebase."""
    report = Scanner().scan_path(root)
    risky = sum(1 for f in report.findings if f.severity.order >= 3)

    log_dir = Path(__file__).parent / "audit-log"
    with LogAppender(
        str(log_dir), agent, rotation=RotationPolicy(max_events_per_segment=100)
    ) as log:
        log.append(
            InferenceEvent.create(
                model_did=agent.did,
                model_version="0.9-deprecated",
                input_bytes=root.encode(),
                output_bytes=str(risky).encode(),
                decision_type="legacy-scan",
                decision_label="findings-reported",
                actor_did="did:example:legacy-ops",
            )
        )
    return risky


def main() -> None:
    agent, status = load_identity()
    print(f"[agent] {agent.did} status={status}")

    if status == "suspended":
        print("[legacy-monitor] this agent is suspended in the registry.")
        print("[legacy-monitor] refusing to run; rotate to a successor DID.")
        sys.exit(0)

    risky = scan_legacy(agent, str(Path(__file__).parent))
    print(f"[scan] high_plus_findings={risky}")


if __name__ == "__main__":
    main()
