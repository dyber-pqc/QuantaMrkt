"""Basic route tests for the QuantaMrkt API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from quantmrkt_api.main import app

client = TestClient(app)


def test_health_check():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_list_models():
    resp = client.get("/v1/models/")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 3
    assert all("namespace" in m for m in data)
    assert any(m["quantum_safe"] is True for m in data)


def test_list_agents():
    resp = client.get("/v1/agents/")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 4
    assert all("did" in a for a in data)


def test_hndl_assess():
    payload = {
        "artifact_type": "model-weights",
        "shelf_life_years": 15,
        "sensitivity": "high",
        "current_encryption": "AES-256-GCM",
    }
    resp = client.post("/v1/hndl/assess", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert isinstance(data["risk_score"], (int, float))
    assert data["risk_score"] > 0
    assert "recommendation" in data
    assert data["migrate_by"] is not None


def test_hndl_assess_pqc_algorithm():
    """A PQC algorithm should produce a low risk score with no migrate_by date."""
    payload = {
        "artifact_type": "dataset",
        "shelf_life_years": 10,
        "sensitivity": "medium",
        "current_encryption": "ML-KEM-768",
    }
    resp = client.post("/v1/hndl/assess", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] < 2.0
    assert data["migrate_by"] is None
