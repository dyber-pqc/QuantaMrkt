"""Finance Copilot -- signs financial analysis reports with PQC provenance."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.identity.agent import AgentIdentity

from pqc_content_provenance import (
    AIGeneratedAssertion,
    ContentManifest,
    GenerationContext,
    ManifestSigner,
    ModelAttribution,
    UsageAssertion,
)
from pqc_audit_log_fs import InferenceEvent, LogAppender, RotationPolicy

IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(data["name"], capabilities=data["capabilities"])


def analyze_portfolio(agent: AgentIdentity, portfolio_data: bytes) -> ContentManifest:
    """Produce a signed analysis report for the given portfolio data."""
    analysis = b"Q4 2026: 12% exposure to quantum-vulnerable assets. Rebalance."
    manifest = ContentManifest.create(
        content=analysis,
        content_type="text/plain",
        model_attribution=ModelAttribution(
            model_did=agent.did,
            model_name="finance-copilot",
            model_version="1.0",
            registry_url=f"https://quantamrkt.com/agents/{agent.did}",
        ),
        generation_context=GenerationContext(
            parameters={"temperature": 0.1}, generated_at="2026-04-20T12:00:00Z"
        ),
        assertions=[
            AIGeneratedAssertion(
                model_name="finance-copilot", model_version="1.0", generator_type="text"
            ),
            UsageAssertion(
                license="proprietary", commercial_use=True, attribution_required=True
            ),
        ],
    )
    return ManifestSigner(agent).sign(manifest)


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    signed = analyze_portfolio(agent, portfolio_data=b"<portfolio csv>")
    print(f"[report] manifest_id={signed.manifest_id}")
    print(f"[report] signature={signed.signature[:24]}...")

    log_dir = Path(__file__).parent / "audit-log"
    with LogAppender(
        str(log_dir), agent, rotation=RotationPolicy(max_events_per_segment=100)
    ) as log:
        log.append(InferenceEvent.create(
            model_did=agent.did,
            model_version="1.0",
            input_bytes=b"<portfolio csv>",
            output_bytes=b"Q4 2026 report",
            decision_type="analysis",
            decision_label="rebalance-recommended",
            actor_did="did:example:user",
        ))
    print(f"[audit] segment sealed at {log_dir}")


if __name__ == "__main__":
    main()
