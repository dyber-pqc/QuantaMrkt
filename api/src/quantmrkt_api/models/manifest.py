"""Pydantic models for model manifests and related types."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ModelMetadata(BaseModel):
    name: str = Field(..., description="Human-readable model name")
    namespace: str = Field(..., description="Registry namespace, e.g. 'dyber-pqc/llm-guard'")
    version: str = Field(..., description="Semantic version")
    description: str = ""
    framework: str = Field("pytorch", description="ML framework used")
    task: str = Field("text-generation", description="Primary task type")
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class FileEntry(BaseModel):
    path: str = Field(..., description="Relative path inside the model package")
    sha256: str = Field(..., description="SHA-256 digest of the file")
    size_bytes: int = Field(..., ge=0)
    content_type: str = "application/octet-stream"


class SignatureEntry(BaseModel):
    algorithm: str = Field(..., description="Signing algorithm, e.g. 'ML-DSA-65'")
    public_key_id: str = Field(..., description="Key identifier or DID")
    signature: str = Field(..., description="Base64-encoded signature value")
    signed_at: datetime = Field(default_factory=datetime.utcnow)
    scope: str = Field("full-manifest", description="What was signed: full-manifest | file-list")


class ProvenanceInfo(BaseModel):
    build_system: str = Field("unknown", description="CI/CD system that built the artifact")
    source_repo: Optional[str] = None
    commit_sha: Optional[str] = None
    build_timestamp: Optional[datetime] = None
    reproducible: bool = False
    slsa_level: int = Field(0, ge=0, le=4, description="SLSA provenance level (0-4)")


class HNDLAssessment(BaseModel):
    artifact_type: str = Field(..., description="e.g. 'model-weights', 'config', 'tokenizer'")
    shelf_life_years: int = Field(..., ge=0)
    sensitivity: str = Field("medium", description="low | medium | high | critical")
    current_encryption: str = Field(..., description="Current encryption algorithm")
    risk_score: float = Field(..., ge=0.0, le=10.0)
    recommendation: str = ""
    migrate_by: Optional[str] = None


class ModelManifest(BaseModel):
    schema_version: str = Field("1.0", description="Manifest schema version")
    metadata: ModelMetadata
    files: list[FileEntry] = Field(default_factory=list)
    signatures: list[SignatureEntry] = Field(default_factory=list)
    provenance: Optional[ProvenanceInfo] = None
    hndl: Optional[HNDLAssessment] = None
    quantum_safe: bool = Field(False, description="Whether all signatures use PQC algorithms")
