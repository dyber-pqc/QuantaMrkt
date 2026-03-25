"""QuantumShield - Post-quantum cryptography toolkit for AI systems."""

__version__ = "0.1.0"

from quantumshield.core.algorithms import KEMAlgorithm, SignatureAlgorithm
from quantumshield.identity.agent import AgentIdentity
from quantumshield.migrator.analyzer import MigrationAgent
from quantumshield.registry.manifest import ModelManifest

__all__ = [
    "AgentIdentity",
    "ModelManifest",
    "MigrationAgent",
    "SignatureAlgorithm",
    "KEMAlgorithm",
]
