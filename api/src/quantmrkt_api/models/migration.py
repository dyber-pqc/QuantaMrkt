"""Pydantic models for PQC migration analysis and reporting."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class MigrationRequest(BaseModel):
    repo_url: str = Field(..., description="Git repository URL to analyse")
    dry_run: bool = Field(False, description="If true, simulate without writing changes")


class VulnerabilityFinding(BaseModel):
    file_path: str
    line_number: int
    algorithm: str = Field(..., description="Detected classical algorithm, e.g. 'RSA-2048'")
    severity: str = Field("medium", description="low | medium | high | critical")
    recommendation: str = ""
    auto_fixable: bool = False


class EffortEstimate(BaseModel):
    total_files: int = Field(0, ge=0)
    affected_files: int = Field(0, ge=0)
    estimated_hours: float = Field(0.0, ge=0.0)
    complexity: str = Field("medium", description="low | medium | high")
    migration_path: str = Field("", description="Recommended migration strategy")


class MigrationReport(BaseModel):
    report_id: str = Field(..., description="Unique report identifier")
    repo_url: str
    status: str = Field("completed", description="pending | running | completed | failed")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    effort: Optional[EffortEstimate] = None
    summary: str = ""
