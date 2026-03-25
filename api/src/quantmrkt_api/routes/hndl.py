"""Routes for Harvest-Now-Decrypt-Later (HNDL) risk assessment."""

from __future__ import annotations

import math
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/hndl", tags=["HNDL"])


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------
class HNDLAssessRequest(BaseModel):
    artifact_type: str = Field(..., description="e.g. 'model-weights', 'api-key', 'dataset'")
    shelf_life_years: int = Field(..., ge=0)
    sensitivity: str = Field("medium", description="low | medium | high | critical")
    current_encryption: str = Field(..., description="Current encryption algorithm")


# ---------------------------------------------------------------------------
# HNDL risk calculation logic
# ---------------------------------------------------------------------------
_SENSITIVITY_WEIGHT = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.5,
    "critical": 5.0,
}

_PQC_ALGORITHMS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-256f",
    "BIKE-L1", "BIKE-L3",
    "HQC-128", "HQC-192", "HQC-256",
    "FrodoKEM-640-AES", "FrodoKEM-976-AES",
}

# Rough estimate: years until a cryptographically-relevant quantum computer (CRQC)
_CRQC_HORIZON_YEARS = 10


def _compute_hndl_risk(
    shelf_life_years: int,
    sensitivity: str,
    current_encryption: str,
) -> tuple[float, str, str | None]:
    """Return (risk_score 0-10, recommendation, migrate_by | None)."""
    is_pqc = current_encryption in _PQC_ALGORITHMS
    sens_w = _SENSITIVITY_WEIGHT.get(sensitivity, 2.0)

    if is_pqc:
        # Already quantum-safe — low residual risk based on shelf-life alone.
        raw = 0.3 * sens_w * math.log1p(shelf_life_years) / math.log1p(30)
        score = round(min(raw, 10.0), 1)
        recommendation = (
            f"Already using PQC algorithm ({current_encryption}). "
            "Re-evaluate when NIST updates standards."
        )
        return score, recommendation, None

    # Classical algorithm — risk grows with sensitivity and shelf-life vs. CRQC horizon.
    exposure = max(shelf_life_years - _CRQC_HORIZON_YEARS, 0)
    urgency = shelf_life_years / max(_CRQC_HORIZON_YEARS, 1)
    raw = sens_w * (1.0 + urgency + 0.5 * math.log1p(exposure))
    score = round(min(raw, 10.0), 1)

    if score >= 7.0:
        recommendation = (
            f"CRITICAL: {current_encryption} offers no post-quantum security. "
            "Migrate to ML-KEM-768 (encryption) or ML-DSA-65 (signing) immediately."
        )
        migrate_by = str(datetime.now(timezone.utc).year + 1)
    elif score >= 4.0:
        recommendation = (
            f"HIGH: {current_encryption} is vulnerable to future quantum attacks. "
            "Plan migration to PQC within the next 2 years."
        )
        migrate_by = str(datetime.now(timezone.utc).year + 2)
    else:
        recommendation = (
            f"MODERATE: {current_encryption} is classically secure for now. "
            "Begin evaluating PQC migration paths."
        )
        migrate_by = str(datetime.now(timezone.utc).year + 4)

    return score, recommendation, migrate_by


# ---------------------------------------------------------------------------
# Mock risk database
# ---------------------------------------------------------------------------
_MOCK_DATABASE = [
    {
        "artifact_type": "model-weights",
        "current_encryption": "AES-256-GCM",
        "sensitivity": "high",
        "shelf_life_years": 15,
        "risk_score": 7.8,
        "recommendation": "Wrap with ML-KEM-768 hybrid encryption.",
    },
    {
        "artifact_type": "api-key",
        "current_encryption": "RSA-2048",
        "sensitivity": "critical",
        "shelf_life_years": 5,
        "risk_score": 8.5,
        "recommendation": "Rotate to PQC-signed tokens immediately.",
    },
    {
        "artifact_type": "dataset",
        "current_encryption": "ML-KEM-768",
        "sensitivity": "medium",
        "shelf_life_years": 10,
        "risk_score": 0.6,
        "recommendation": "Already quantum-safe. No action required.",
    },
    {
        "artifact_type": "config",
        "current_encryption": "ECDSA-P256",
        "sensitivity": "low",
        "shelf_life_years": 3,
        "risk_score": 2.3,
        "recommendation": "Low urgency. Evaluate ML-DSA-44 for next rotation.",
    },
    {
        "artifact_type": "tokenizer",
        "current_encryption": "ECDH-P384",
        "sensitivity": "medium",
        "shelf_life_years": 8,
        "risk_score": 5.1,
        "recommendation": "Plan migration to ML-KEM-768 within 2 years.",
    },
]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/assess")
async def assess_hndl_risk(body: HNDLAssessRequest):
    """Compute HNDL risk score for the given artifact."""
    score, recommendation, migrate_by = _compute_hndl_risk(
        shelf_life_years=body.shelf_life_years,
        sensitivity=body.sensitivity,
        current_encryption=body.current_encryption,
    )
    return {
        "artifact_type": body.artifact_type,
        "shelf_life_years": body.shelf_life_years,
        "sensitivity": body.sensitivity,
        "current_encryption": body.current_encryption,
        "risk_score": score,
        "recommendation": recommendation,
        "migrate_by": migrate_by,
    }


@router.get("/database")
async def get_risk_database():
    """Return the mock HNDL risk database."""
    return _MOCK_DATABASE
