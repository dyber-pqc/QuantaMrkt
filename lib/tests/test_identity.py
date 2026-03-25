"""Tests for agent identity management."""

import json

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity
from quantumshield.identity.credentials import ActionCredential


def test_agent_create_default():
    """Test that AgentIdentity.create() produces a valid identity."""
    agent = AgentIdentity.create("test-agent")
    assert agent.name == "test-agent"
    assert agent.did.startswith("did:pqaid:")
    assert agent.signing_keypair is not None
    assert agent.signing_keypair.algorithm == SignatureAlgorithm.ML_DSA_65
    assert agent.capabilities == []


def test_agent_create_with_capabilities():
    """Test agent creation with custom capabilities."""
    caps = ["sign", "verify", "delegate"]
    agent = AgentIdentity.create("cap-agent", capabilities=caps)
    assert agent.capabilities == caps


def test_agent_create_custom_algorithm():
    """Test agent creation with a non-default algorithm."""
    agent = AgentIdentity.create("ml87-agent", algorithm=SignatureAlgorithm.ML_DSA_87)
    assert agent.signing_keypair.algorithm == SignatureAlgorithm.ML_DSA_87


def test_agent_did_uniqueness():
    """Test that two agents get distinct DIDs."""
    a1 = AgentIdentity.create("agent-1")
    a2 = AgentIdentity.create("agent-2")
    assert a1.did != a2.did


def test_agent_sign_action():
    """Test signing an action credential."""
    agent = AgentIdentity.create("signer")
    credential = agent.sign_action("model.sign", "org/my-model:v1")
    assert isinstance(credential, ActionCredential)
    assert credential.signer_did == agent.did
    assert credential.action == "model.sign"
    assert credential.target == "org/my-model:v1"
    assert isinstance(credential.signature, bytes)
    assert len(credential.signature) > 0


def test_agent_export():
    """Test that export produces valid JSON with public info only."""
    agent = AgentIdentity.create("export-agent", capabilities=["sign"])
    exported = agent.export()
    data = json.loads(exported)
    assert data["did"] == agent.did
    assert data["name"] == "export-agent"
    assert "public_key" in data
    assert "private_key" not in data
    assert data["capabilities"] == ["sign"]
