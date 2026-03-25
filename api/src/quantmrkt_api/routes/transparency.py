"""Routes for the transparency log and Merkle proof verification."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/transparency", tags=["Transparency"])

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------
_MOCK_LOG_ENTRIES = [
    {
        "entry_id": "txn-0001",
        "timestamp": "2026-03-10T08:12:00Z",
        "action": "model:push",
        "actor": "did:web:quantamrkt.io:agents:alpha-1",
        "resource": "dyber-pqc/llm-guard@2.1.0",
        "hash": "sha256:a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    },
    {
        "entry_id": "txn-0002",
        "timestamp": "2026-03-10T09:45:00Z",
        "action": "model:sign",
        "actor": "did:web:quantamrkt.io:agents:alpha-1",
        "resource": "dyber-pqc/llm-guard@2.1.0",
        "hash": "sha256:b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
    },
    {
        "entry_id": "txn-0003",
        "timestamp": "2026-03-11T14:30:00Z",
        "action": "migrate:analyze",
        "actor": "did:web:quantamrkt.io:agents:beta-scanner",
        "resource": "https://github.com/example-org/legacy-crypto-service",
        "hash": "sha256:c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    },
    {
        "entry_id": "txn-0004",
        "timestamp": "2026-03-12T11:00:00Z",
        "action": "agent:register",
        "actor": "did:web:quantamrkt.io:agents:alpha-1",
        "resource": "did:web:quantamrkt.io:agents:delta-ops",
        "hash": "sha256:d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
    },
    {
        "entry_id": "txn-0005",
        "timestamp": "2026-03-13T16:22:00Z",
        "action": "hndl:assess",
        "actor": "did:web:quantamrkt.io:agents:delta-ops",
        "resource": "dyber-pqc/embed-qsafe@1.4.0",
        "hash": "sha256:e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
    },
]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/log")
async def get_transparency_log():
    """Return recent transparency-log entries."""
    return _MOCK_LOG_ENTRIES


@router.get("/proof/{entry_id}")
async def get_merkle_proof(entry_id: str):
    """Return a mock Merkle inclusion proof for the given log entry."""
    return {
        "entry_id": entry_id,
        "root_hash": "sha256:f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
        "leaf_hash": "sha256:a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        "proof_hashes": [
            "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "sha256:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c",
            "sha256:3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d",
        ],
        "tree_size": 5,
        "leaf_index": 0,
        "verified": True,
    }
