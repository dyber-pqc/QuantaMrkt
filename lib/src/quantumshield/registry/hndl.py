"""Harvest Now, Decrypt Later (HNDL) risk assessment calculator.

Implements the HNDL risk scoring model for evaluating the urgency
of migrating cryptographic assets to post-quantum algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ArtifactType(str, Enum):
    """Types of cryptographic artifacts that may be at HNDL risk."""

    MODEL_WEIGHTS = "model_weights"
    API_KEYS = "api_keys"
    USER_DATA = "user_data"
    TRAINING_DATA = "training_data"
    INFERENCE_LOGS = "inference_logs"
    CONFIGURATION = "configuration"
    SOURCE_CODE = "source_code"
    CERTIFICATES = "certificates"
    SIGNING_KEYS = "signing_keys"


class Sensitivity(str, Enum):
    """Data sensitivity classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class CurrentEncryption(str, Enum):
    """Current encryption status of an artifact."""

    NONE = "none"
    AES_128 = "aes_128"
    AES_256 = "aes_256"
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    CHACHA20 = "chacha20"
    PQ_HYBRID = "pq_hybrid"
    PQ_NATIVE = "pq_native"


# Sensitivity multipliers: how much more urgent migration is by sensitivity level
SENSITIVITY_MULTIPLIERS: dict[str, float] = {
    "public": 0.5,
    "internal": 1.0,
    "confidential": 1.5,
    "secret": 2.0,
    "top_secret": 3.0,
}

# Quantum vulnerability scores for current encryption schemes
# Higher = more vulnerable to quantum attack
ENCRYPTION_VULNERABILITY: dict[str, float] = {
    "none": 10.0,
    "aes_128": 3.0,       # Grover's halves effective key length
    "aes_256": 1.0,       # Still 128-bit security post-quantum
    "rsa_2048": 9.0,      # Fully broken by Shor's algorithm
    "rsa_4096": 8.5,      # Fully broken by Shor's algorithm
    "ecdsa_p256": 9.0,    # Fully broken by Shor's algorithm
    "ecdsa_p384": 8.5,    # Fully broken by Shor's algorithm
    "chacha20": 1.5,      # Symmetric, relatively safe
    "pq_hybrid": 0.5,     # Already partially migrated
    "pq_native": 0.0,     # Already migrated
}

# Base risk scores for artifact types (how attractive to HNDL attackers)
ARTIFACT_BASE_RISK: dict[str, float] = {
    "model_weights": 7.0,
    "api_keys": 8.0,
    "user_data": 9.0,
    "training_data": 6.0,
    "inference_logs": 4.0,
    "configuration": 3.0,
    "source_code": 5.0,
    "certificates": 8.5,
    "signing_keys": 9.5,
}


@dataclass
class HNDLAssessment:
    """Result of an HNDL risk assessment for an artifact."""

    artifact_type: str
    shelf_life_years: int
    sensitivity: str
    current_encryption: str
    risk_score: float
    risk_level: str
    quantum_vulnerability: float
    time_pressure: float
    recommendation: str
    migration_priority: int
    details: dict


def calculate_hndl_risk(
    artifact_type: str,
    shelf_life_years: int,
    sensitivity: str,
    current_encryption: str,
) -> dict:
    """Calculate the HNDL (Harvest Now, Decrypt Later) risk for an artifact.

    The risk model considers:
    1. The artifact's base attractiveness to HNDL attackers
    2. How long the data needs to remain confidential (shelf life)
    3. The sensitivity classification of the data
    4. How vulnerable the current encryption is to quantum attack

    The core formula:
        risk_score = (artifact_risk * sensitivity_mult * quantum_vuln * time_pressure) / 10

    Where time_pressure increases with shelf life (data that must stay secret
    longer is at higher risk from HNDL attacks).

    Args:
        artifact_type: Type of artifact (e.g., "model_weights", "user_data").
        shelf_life_years: How many years the data must remain confidential.
        sensitivity: Sensitivity level ("public" through "top_secret").
        current_encryption: Current encryption scheme (e.g., "rsa_2048", "aes_256").

    Returns:
        A dict containing risk_score, risk_level, recommendation, and supporting details.
    """
    # Look up base scores, with safe defaults
    artifact_risk = ARTIFACT_BASE_RISK.get(artifact_type, 5.0)
    sensitivity_mult = SENSITIVITY_MULTIPLIERS.get(sensitivity, 1.0)
    quantum_vuln = ENCRYPTION_VULNERABILITY.get(current_encryption, 5.0)

    # Time pressure: increases logarithmically with shelf life
    # Short-lived data (< 2 years) has lower HNDL risk because quantum computers
    # are unlikely to be available in that timeframe
    if shelf_life_years <= 0:
        time_pressure = 0.1
    elif shelf_life_years <= 2:
        time_pressure = 0.5
    elif shelf_life_years <= 5:
        time_pressure = 1.0
    elif shelf_life_years <= 10:
        time_pressure = 1.5
    elif shelf_life_years <= 20:
        time_pressure = 2.0
    else:
        time_pressure = 2.5

    # Core risk calculation
    raw_score = artifact_risk * sensitivity_mult * quantum_vuln * time_pressure
    # Normalize to 0-10 scale
    risk_score = min(10.0, round(raw_score / 10.0, 2))

    # Determine risk level
    if risk_score >= 8.0:
        risk_level = "CRITICAL"
    elif risk_score >= 6.0:
        risk_level = "HIGH"
    elif risk_score >= 4.0:
        risk_level = "MEDIUM"
    elif risk_score >= 2.0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    # Migration priority (1 = most urgent, 5 = least urgent)
    if risk_score >= 8.0:
        migration_priority = 1
    elif risk_score >= 6.0:
        migration_priority = 2
    elif risk_score >= 4.0:
        migration_priority = 3
    elif risk_score >= 2.0:
        migration_priority = 4
    else:
        migration_priority = 5

    # Generate recommendation text
    recommendation = _generate_recommendation(
        risk_level, artifact_type, current_encryption, shelf_life_years
    )

    assessment = HNDLAssessment(
        artifact_type=artifact_type,
        shelf_life_years=shelf_life_years,
        sensitivity=sensitivity,
        current_encryption=current_encryption,
        risk_score=risk_score,
        risk_level=risk_level,
        quantum_vulnerability=quantum_vuln,
        time_pressure=time_pressure,
        recommendation=recommendation,
        migration_priority=migration_priority,
        details={
            "artifact_base_risk": artifact_risk,
            "sensitivity_multiplier": sensitivity_mult,
            "quantum_vulnerability": quantum_vuln,
            "time_pressure": time_pressure,
            "raw_score": raw_score,
            "normalized_score": risk_score,
        },
    )

    return {
        "artifact_type": assessment.artifact_type,
        "shelf_life_years": assessment.shelf_life_years,
        "sensitivity": assessment.sensitivity,
        "current_encryption": assessment.current_encryption,
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "quantum_vulnerability": assessment.quantum_vulnerability,
        "time_pressure": assessment.time_pressure,
        "recommendation": assessment.recommendation,
        "migration_priority": assessment.migration_priority,
        "details": assessment.details,
    }


def _generate_recommendation(
    risk_level: str,
    artifact_type: str,
    current_encryption: str,
    shelf_life_years: int,
) -> str:
    """Generate a human-readable recommendation based on the risk assessment."""
    if current_encryption in ("pq_native", "pq_hybrid"):
        return (
            f"The {artifact_type} is already using post-quantum cryptography. "
            "Continue monitoring NIST standards for algorithm updates."
        )

    if risk_level == "CRITICAL":
        return (
            f"IMMEDIATE ACTION REQUIRED: The {artifact_type} using {current_encryption} "
            f"with a {shelf_life_years}-year shelf life is at critical HNDL risk. "
            "Begin migration to ML-KEM-768/ML-DSA-65 immediately. "
            "Consider PQ-hybrid mode as an interim step if full migration cannot be completed within 30 days."
        )

    if risk_level == "HIGH":
        return (
            f"HIGH PRIORITY: The {artifact_type} using {current_encryption} "
            f"should be migrated to post-quantum algorithms within 90 days. "
            "Recommended target: ML-KEM-768 for encryption, ML-DSA-65 for signatures. "
            "Develop a migration plan and begin testing PQ algorithms in staging."
        )

    if risk_level == "MEDIUM":
        return (
            f"PLANNED MIGRATION: The {artifact_type} using {current_encryption} "
            f"should be included in your PQC migration roadmap. "
            "Target migration within 6-12 months. Begin evaluating PQ algorithm "
            "compatibility with your existing infrastructure."
        )

    if risk_level == "LOW":
        return (
            f"MONITOR: The {artifact_type} has low HNDL risk currently. "
            "Include in long-term PQC migration plans. Review risk assessment "
            "annually as quantum computing capabilities advance."
        )

    return (
        f"MINIMAL RISK: The {artifact_type} has minimal HNDL exposure. "
        "No immediate action needed. Continue following PQC standardization developments."
    )
