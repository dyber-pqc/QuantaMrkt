"""PQC mutual authentication handshake for MCP peers."""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from quantumshield.core.algorithms import SignatureAlgorithm
from quantumshield.core.signatures import sign, verify
from quantumshield.identity.agent import AgentIdentity

from pqc_mcp_transport.errors import HandshakeError
from pqc_mcp_transport.session import PQCSession


@dataclass
class HandshakeRequest:
    """Client's handshake initiation."""

    client_did: str
    client_public_key: str  # hex
    algorithm: str
    timestamp: str
    nonce: str
    signature: str  # hex

    def to_dict(self) -> dict:
        return {
            "type": "pqc_handshake_request",
            "client_did": self.client_did,
            "client_public_key": self.client_public_key,
            "algorithm": self.algorithm,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HandshakeRequest:
        return cls(
            client_did=data["client_did"],
            client_public_key=data["client_public_key"],
            algorithm=data["algorithm"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            signature=data["signature"],
        )


@dataclass
class HandshakeResponse:
    """Server's handshake response."""

    server_did: str
    server_public_key: str  # hex
    algorithm: str
    client_nonce: str  # echo back
    server_nonce: str
    signature: str  # hex
    session_id: str

    def to_dict(self) -> dict:
        return {
            "type": "pqc_handshake_response",
            "server_did": self.server_did,
            "server_public_key": self.server_public_key,
            "algorithm": self.algorithm,
            "client_nonce": self.client_nonce,
            "server_nonce": self.server_nonce,
            "signature": self.signature,
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HandshakeResponse:
        return cls(
            server_did=data["server_did"],
            server_public_key=data["server_public_key"],
            algorithm=data["algorithm"],
            client_nonce=data["client_nonce"],
            server_nonce=data["server_nonce"],
            signature=data["signature"],
            session_id=data["session_id"],
        )


class PQCHandshake:
    """Mutual PQC authentication handshake between MCP client and server."""

    @staticmethod
    def _sign_payload(payload: bytes, identity: AgentIdentity) -> bytes:
        """Hash and sign a payload."""
        msg_hash = hashlib.sha3_256(payload).digest()
        return sign(msg_hash, identity.signing_keypair)

    @staticmethod
    def _verify_payload(
        payload: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: SignatureAlgorithm,
    ) -> bool:
        """Hash and verify a payload signature."""
        msg_hash = hashlib.sha3_256(payload).digest()
        return verify(msg_hash, signature, public_key, algorithm)

    @staticmethod
    def initiate(identity: AgentIdentity) -> tuple[HandshakeRequest, str]:
        """Create a handshake request.

        Returns the request and the nonce (needed later to complete the handshake).
        """
        nonce = os.urandom(16).hex()
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = f"{identity.did}:{nonce}:{timestamp}".encode("utf-8")
        sig = PQCHandshake._sign_payload(payload, identity)

        request = HandshakeRequest(
            client_did=identity.did,
            client_public_key=identity.signing_keypair.public_key.hex(),
            algorithm=identity.signing_keypair.algorithm.value,
            timestamp=timestamp,
            nonce=nonce,
            signature=sig.hex(),
        )
        return request, nonce

    @staticmethod
    def respond(
        request: HandshakeRequest, server_identity: AgentIdentity
    ) -> HandshakeResponse:
        """Verify the client's request and create a signed response.

        Raises :class:`HandshakeError` if the client's signature is invalid.
        """
        # Verify client signature
        payload = f"{request.client_did}:{request.nonce}:{request.timestamp}".encode(
            "utf-8"
        )
        client_pub = bytes.fromhex(request.client_public_key)
        algorithm = SignatureAlgorithm(request.algorithm)
        client_sig = bytes.fromhex(request.signature)

        if not PQCHandshake._verify_payload(payload, client_sig, client_pub, algorithm):
            raise HandshakeError("Client handshake signature verification failed")

        # Create response
        session_id = uuid.uuid4().hex
        server_nonce = os.urandom(16).hex()

        resp_payload = (
            f"{server_identity.did}:{request.nonce}:{server_nonce}:{session_id}"
        ).encode("utf-8")
        sig = PQCHandshake._sign_payload(resp_payload, server_identity)

        return HandshakeResponse(
            server_did=server_identity.did,
            server_public_key=server_identity.signing_keypair.public_key.hex(),
            algorithm=server_identity.signing_keypair.algorithm.value,
            client_nonce=request.nonce,
            server_nonce=server_nonce,
            signature=sig.hex(),
            session_id=session_id,
        )

    @staticmethod
    def complete(
        response: HandshakeResponse,
        client_identity: AgentIdentity,
        original_nonce: str,
    ) -> PQCSession:
        """Verify the server's response and create a session.

        Raises :class:`HandshakeError` on verification failure.
        """
        # Verify nonce echo
        if response.client_nonce != original_nonce:
            raise HandshakeError("Server did not echo back the correct client nonce")

        # Verify server signature
        resp_payload = (
            f"{response.server_did}:{response.client_nonce}:{response.server_nonce}:{response.session_id}"
        ).encode("utf-8")
        server_pub = bytes.fromhex(response.server_public_key)
        algorithm = SignatureAlgorithm(response.algorithm)
        server_sig = bytes.fromhex(response.signature)

        if not PQCHandshake._verify_payload(
            resp_payload, server_sig, server_pub, algorithm
        ):
            raise HandshakeError("Server handshake signature verification failed")

        return PQCSession(
            session_id=response.session_id,
            local_identity=client_identity,
            peer_did=response.server_did,
            peer_public_key=server_pub,
            peer_algorithm=algorithm,
        )
