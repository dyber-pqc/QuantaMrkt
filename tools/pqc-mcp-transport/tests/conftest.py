"""Shared pytest fixtures for PQC MCP Transport tests."""

from __future__ import annotations

import pytest
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.signer import MessageSigner


@pytest.fixture
def client_identity() -> AgentIdentity:
    """An AgentIdentity representing a client."""
    return AgentIdentity.create("test-client", capabilities=["tools:call"])


@pytest.fixture
def server_identity() -> AgentIdentity:
    """An AgentIdentity representing a server."""
    return AgentIdentity.create("test-server", capabilities=["tools:serve"])


@pytest.fixture
def message_signer(client_identity: AgentIdentity) -> MessageSigner:
    """A MessageSigner backed by the client identity."""
    return MessageSigner(client_identity)


@pytest.fixture
def sample_tool_call() -> dict:
    """A sample JSON-RPC tool call message."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "abc123",
        "params": {
            "name": "greet",
            "arguments": {"name": "World"},
        },
    }


@pytest.fixture
def sample_response() -> dict:
    """A sample JSON-RPC response message."""
    return {
        "jsonrpc": "2.0",
        "id": "abc123",
        "result": {
            "content": "Hello, World!",
        },
    }
