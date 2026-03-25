"""Routes for the model registry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, status

router = APIRouter(prefix="/models", tags=["Models"])

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------
_MOCK_MODELS = [
    {
        "namespace": "dyber-pqc/llm-guard",
        "name": "LLM-Guard",
        "version": "2.1.0",
        "framework": "pytorch",
        "task": "text-classification",
        "quantum_safe": True,
        "tags": ["safety", "pqc", "guard-model"],
    },
    {
        "namespace": "dyber-pqc/embed-qsafe",
        "name": "Embed-QSafe",
        "version": "1.4.0",
        "framework": "onnx",
        "task": "feature-extraction",
        "quantum_safe": True,
        "tags": ["embeddings", "pqc"],
    },
    {
        "namespace": "community/sentiment-v3",
        "name": "Sentiment-v3",
        "version": "3.0.1",
        "framework": "pytorch",
        "task": "text-classification",
        "quantum_safe": False,
        "tags": ["sentiment", "nlp"],
    },
]

_MOCK_MANIFEST: dict[str, Any] = {
    "schema_version": "1.0",
    "metadata": {
        "name": "LLM-Guard",
        "namespace": "dyber-pqc/llm-guard",
        "version": "2.1.0",
        "description": "Quantum-safe guardrail model for LLM output filtering.",
        "framework": "pytorch",
        "task": "text-classification",
        "tags": ["safety", "pqc", "guard-model"],
        "created_at": "2025-11-01T10:00:00Z",
        "updated_at": "2026-02-15T08:30:00Z",
    },
    "files": [
        {
            "path": "model.safetensors",
            "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "size_bytes": 524_288_000,
            "content_type": "application/octet-stream",
        },
        {
            "path": "config.json",
            "sha256": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
            "size_bytes": 2048,
            "content_type": "application/json",
        },
    ],
    "signatures": [
        {
            "algorithm": "ML-DSA-65",
            "public_key_id": "did:web:quantamrkt.io:keys:ml-dsa-65-prod-1",
            "signature": "MLDSA65SIG_BASE64_PLACEHOLDER==",
            "signed_at": "2026-02-15T08:35:00Z",
            "scope": "full-manifest",
        }
    ],
    "provenance": {
        "build_system": "github-actions",
        "source_repo": "https://github.com/dyber-pqc/llm-guard",
        "commit_sha": "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
        "build_timestamp": "2026-02-15T08:20:00Z",
        "reproducible": True,
        "slsa_level": 3,
    },
    "hndl": {
        "artifact_type": "model-weights",
        "shelf_life_years": 10,
        "sensitivity": "high",
        "current_encryption": "ML-KEM-768",
        "risk_score": 2.1,
        "recommendation": "Already quantum-safe. Re-assess in 2030.",
        "migrate_by": None,
    },
    "quantum_safe": True,
}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/")
async def list_models():
    """Return a list of model summaries in the registry."""
    return _MOCK_MODELS


@router.get("/{namespace:path}/verify")
async def verify_model(namespace: str):
    """Return a mock verification result for the given model namespace."""
    return {
        "namespace": namespace,
        "verified": True,
        "algorithm": "ML-DSA-65",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "signer": "did:web:quantamrkt.io:keys:ml-dsa-65-prod-1",
        "details": "All file hashes match. Signature valid under ML-DSA-65.",
    }


@router.get("/{namespace:path}")
async def get_model_manifest(namespace: str):
    """Return the manifest for a model identified by its namespace path."""
    manifest = {**_MOCK_MANIFEST}
    manifest["metadata"] = {**_MOCK_MANIFEST["metadata"], "namespace": namespace}
    return manifest


@router.post("/{namespace:path}", status_code=status.HTTP_201_CREATED)
async def push_manifest(namespace: str, body: dict):
    """Accept a manifest push and return confirmation."""
    return {
        "namespace": namespace,
        "status": "accepted",
        "message": "Manifest received and queued for verification.",
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
