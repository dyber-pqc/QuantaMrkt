"""Routes for agent identity management."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, status

from quantmrkt_api.models.agent import AgentRegistration

router = APIRouter(prefix="/agents", tags=["Agents"])

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------
_MOCK_AGENTS = [
    {
        "did": "did:web:quantamrkt.io:agents:alpha-1",
        "name": "Alpha-Signer",
        "algorithm": "ML-DSA-65",
        "capabilities": ["model:push", "model:sign", "model:verify"],
        "delegated_by": None,
        "status": "active",
        "created_at": "2025-09-15T12:00:00Z",
    },
    {
        "did": "did:web:quantamrkt.io:agents:beta-scanner",
        "name": "Beta-Scanner",
        "algorithm": "ML-DSA-44",
        "capabilities": ["migrate:analyze", "migrate:run"],
        "delegated_by": "did:web:quantamrkt.io:agents:alpha-1",
        "status": "active",
        "created_at": "2025-10-01T09:30:00Z",
    },
    {
        "did": "did:web:quantamrkt.io:agents:gamma-auditor",
        "name": "Gamma-Auditor",
        "algorithm": "SLH-DSA-SHA2-128f",
        "capabilities": ["transparency:read", "transparency:verify"],
        "delegated_by": None,
        "status": "active",
        "created_at": "2025-11-20T14:15:00Z",
    },
    {
        "did": "did:web:quantamrkt.io:agents:delta-ops",
        "name": "Delta-Ops",
        "algorithm": "ML-DSA-87",
        "capabilities": ["model:push", "model:sign", "migrate:analyze", "hndl:assess"],
        "delegated_by": "did:web:quantamrkt.io:agents:alpha-1",
        "status": "suspended",
        "created_at": "2026-01-05T11:00:00Z",
    },
]

_AGENTS_BY_ID = {a["did"].rsplit(":", 1)[-1]: a for a in _MOCK_AGENTS}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/")
async def list_agents():
    """Return all registered agents."""
    return _MOCK_AGENTS


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    """Return a single agent by its short ID."""
    if agent_id in _AGENTS_BY_ID:
        return _AGENTS_BY_ID[agent_id]
    return {
        "did": f"did:web:quantamrkt.io:agents:{agent_id}",
        "name": agent_id,
        "algorithm": "ML-DSA-65",
        "capabilities": [],
        "delegated_by": None,
        "status": "unknown",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def register_agent(body: AgentRegistration):
    """Register a new agent and return its identity."""
    now = datetime.now(timezone.utc).isoformat()
    agent_id = body.name.lower().replace(" ", "-")
    return {
        "did": f"did:web:quantamrkt.io:agents:{agent_id}",
        "name": body.name,
        "algorithm": body.algorithm,
        "capabilities": body.capabilities,
        "delegated_by": body.delegated_by,
        "status": "active",
        "created_at": now,
    }


@router.get("/{agent_id}/verify")
async def verify_agent(agent_id: str):
    """Return a mock identity-verification result."""
    return {
        "agent_id": agent_id,
        "verified": True,
        "algorithm": "ML-DSA-65",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "details": "Agent identity verified. DID document resolved and signature valid.",
    }
