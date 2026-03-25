"""Tests for the registry module, including the HNDL risk calculator."""

from quantumshield.registry.hndl import calculate_hndl_risk


def test_hndl_critical_risk():
    """Test that high-sensitivity RSA-encrypted data with long shelf life is CRITICAL."""
    result = calculate_hndl_risk(
        artifact_type="user_data",
        shelf_life_years=15,
        sensitivity="secret",
        current_encryption="rsa_2048",
    )
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 8.0
    assert result["migration_priority"] == 1
    assert "IMMEDIATE" in result["recommendation"]


def test_hndl_minimal_risk_pq_native():
    """Test that PQ-native encryption results in minimal risk."""
    result = calculate_hndl_risk(
        artifact_type="configuration",
        shelf_life_years=1,
        sensitivity="internal",
        current_encryption="pq_native",
    )
    assert result["risk_level"] == "MINIMAL"
    assert result["risk_score"] < 2.0
    assert result["migration_priority"] == 5
    assert "already using post-quantum" in result["recommendation"]


def test_hndl_medium_risk_aes_cbc():
    """Test medium-sensitivity AES-128 data lands in a reasonable risk range."""
    result = calculate_hndl_risk(
        artifact_type="training_data",
        shelf_life_years=5,
        sensitivity="confidential",
        current_encryption="aes_128",
    )
    # AES-128 has quantum_vuln=3.0, not as severe as RSA
    assert result["risk_level"] in ("LOW", "MEDIUM")
    assert result["quantum_vulnerability"] == 3.0


def test_hndl_zero_shelf_life():
    """Test that zero shelf life results in low time pressure."""
    result = calculate_hndl_risk(
        artifact_type="signing_keys",
        shelf_life_years=0,
        sensitivity="top_secret",
        current_encryption="ecdsa_p256",
    )
    assert result["time_pressure"] == 0.1
    # Even with top_secret ECDSA, near-zero shelf life reduces overall risk
    assert result["risk_score"] < 5.0


def test_hndl_public_data_low_risk():
    """Test that public data has reduced sensitivity multiplier."""
    result = calculate_hndl_risk(
        artifact_type="inference_logs",
        shelf_life_years=3,
        sensitivity="public",
        current_encryption="rsa_2048",
    )
    assert result["details"]["sensitivity_multiplier"] == 0.5
    # Should be lower than the same config with higher sensitivity
    secret_result = calculate_hndl_risk(
        artifact_type="inference_logs",
        shelf_life_years=3,
        sensitivity="secret",
        current_encryption="rsa_2048",
    )
    assert result["risk_score"] < secret_result["risk_score"]


def test_hndl_result_structure():
    """Test that the result dict has all expected fields."""
    result = calculate_hndl_risk(
        artifact_type="model_weights",
        shelf_life_years=10,
        sensitivity="confidential",
        current_encryption="aes_256",
    )
    expected_keys = {
        "artifact_type", "shelf_life_years", "sensitivity", "current_encryption",
        "risk_score", "risk_level", "quantum_vulnerability", "time_pressure",
        "recommendation", "migration_priority", "details",
    }
    assert set(result.keys()) == expected_keys
    assert isinstance(result["details"], dict)
    assert "raw_score" in result["details"]
