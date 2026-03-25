"""Pydantic models for agent identity and credentials."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AgentIdentity(BaseModel):
    did: str = Field(..., description="Decentralised identifier, e.g. 'did:web:quantamrkt.io:agents:alpha-1'")
    name: str = Field(..., description="Human-readable agent name")
    algorithm: str = Field("ML-DSA-65", description="Primary signing algorithm")
    capabilities: list[str] = Field(default_factory=list, description="Granted capabilities")
    delegated_by: Optional[str] = Field(None, description="DID of the delegating principal")
    status: str = Field("active", description="active | suspended | revoked")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AgentRegistration(BaseModel):
    name: str = Field(..., description="Requested agent name")
    algorithm: str = Field("ML-DSA-65", description="Signing algorithm to use")
    capabilities: list[str] = Field(default_factory=list)
    delegated_by: Optional[str] = None


class ActionCredential(BaseModel):
    credential_id: str = Field(..., description="Unique credential identifier")
    agent_did: str = Field(..., description="DID of the agent this credential belongs to")
    action: str = Field(..., description="Authorised action, e.g. 'model:push'")
    scope: str = Field("*", description="Scope restriction")
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    signature: str = Field(..., description="PQC signature over the credential payload")
