"""Code Reviewer -- reviews PRs over PQC-secured MCP; signs the lint report."""

from __future__ import annotations

import json
from pathlib import Path

from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport import MessageSigner
from pqc_lint import Scanner


IDENTITY_FILE = Path(__file__).parent / "identity.json"


def load_identity() -> AgentIdentity:
    data = json.loads(IDENTITY_FILE.read_text())
    return AgentIdentity.create(data["name"], capabilities=data["capabilities"])


def review_diff(agent: AgentIdentity, diff_root: str) -> dict:
    """Scan a directory (mock PR checkout) and return a signed MCP message."""
    scanner = Scanner()
    report = scanner.scan_path(diff_root)

    findings = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "file": f.file,
            "line": f.line,
            "message": f.message,
        }
        for f in report.findings
    ]

    review_message = {
        "jsonrpc": "2.0",
        "id": "review-1",
        "method": "code_review.post",
        "params": {
            "agent_did": agent.did,
            "files_scanned": report.files_scanned,
            "findings": findings,
            "verdict": "approved" if not findings else "changes-requested",
        },
    }
    return MessageSigner(agent).sign_message(review_message)


def main() -> None:
    agent = load_identity()
    print(f"[agent] {agent.did}")

    # Use this package's own directory as a trivial mock PR checkout.
    mock_pr_root = str(Path(__file__).parent)
    signed = review_diff(agent, mock_pr_root)

    pqc = signed["_pqc"]
    print(f"[review] files_scanned={signed['params']['files_scanned']}")
    print(f"[review] findings={len(signed['params']['findings'])}")
    print(f"[review] verdict={signed['params']['verdict']}")
    print(f"[mcp] signed by {pqc['signer_did']} ({pqc['algorithm']})")
    print(f"[mcp] signature={pqc['signature'][:24]}...")


if __name__ == "__main__":
    main()
