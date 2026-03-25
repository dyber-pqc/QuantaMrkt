"""Routes for PQC migration analysis and execution."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from quantmrkt_api.models.migration import MigrationRequest

router = APIRouter(prefix="/migrate", tags=["Migration"])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/analyze")
async def analyze_repo(body: MigrationRequest):
    """Kick off a migration analysis for the given repository."""
    return {
        "report_id": "rpt-20260315-a1b2c3",
        "repo_url": body.repo_url,
        "status": "analyzing",
        "message": "Static analysis started. Poll GET /v1/migrate/report/{report_id} for results.",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/run")
async def run_migration(body: MigrationRequest):
    """Start (or dry-run) the automated PQC migration."""
    return {
        "report_id": "rpt-20260315-d4e5f6",
        "repo_url": body.repo_url,
        "dry_run": body.dry_run,
        "status": "migrating" if not body.dry_run else "dry-run",
        "message": "Migration initiated."
        + (" (dry-run mode — no files will be modified)" if body.dry_run else ""),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/report/{report_id}")
async def get_report(report_id: str):
    """Return a mock migration report."""
    return {
        "report_id": report_id,
        "repo_url": "https://github.com/example-org/legacy-crypto-service",
        "status": "completed",
        "started_at": "2026-03-15T10:00:00Z",
        "completed_at": "2026-03-15T10:04:32Z",
        "findings": [
            {
                "file_path": "src/auth/token.py",
                "line_number": 42,
                "algorithm": "RSA-2048",
                "severity": "high",
                "recommendation": "Replace with ML-DSA-65 for signing or ML-KEM-768 for key exchange.",
                "auto_fixable": True,
            },
            {
                "file_path": "src/crypto/encrypt.py",
                "line_number": 18,
                "algorithm": "ECDH-P256",
                "severity": "high",
                "recommendation": "Replace with ML-KEM-768.",
                "auto_fixable": True,
            },
            {
                "file_path": "src/tls/config.py",
                "line_number": 7,
                "algorithm": "ECDSA-P256",
                "severity": "medium",
                "recommendation": "Replace with ML-DSA-44 or SLH-DSA-SHA2-128f.",
                "auto_fixable": False,
            },
            {
                "file_path": "tests/conftest.py",
                "line_number": 91,
                "algorithm": "RSA-4096",
                "severity": "low",
                "recommendation": "Test fixture — update to match production algorithm after migration.",
                "auto_fixable": True,
            },
        ],
        "effort": {
            "total_files": 128,
            "affected_files": 4,
            "estimated_hours": 6.5,
            "complexity": "medium",
            "migration_path": "Hybrid classical+PQC first, then full PQC cutover.",
        },
        "summary": (
            "Found 4 classical-crypto usages across 4 files. "
            "3 are auto-fixable. Estimated migration effort: 6.5 hours (medium complexity). "
            "Recommended path: deploy hybrid wrappers, validate, then cut over to pure PQC."
        ),
    }
