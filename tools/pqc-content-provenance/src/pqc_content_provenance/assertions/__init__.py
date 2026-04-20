"""Assertion registry -- maps label -> Assertion subclass."""

from __future__ import annotations

from pqc_content_provenance.assertions.ai_generated import AIGeneratedAssertion
from pqc_content_provenance.assertions.base import Assertion
from pqc_content_provenance.assertions.training import TrainingAssertion
from pqc_content_provenance.assertions.usage import UsageAssertion

ASSERTION_REGISTRY: dict[str, type[Assertion]] = {
    "c2pa.ai_generated": AIGeneratedAssertion,
    "c2pa.training": TrainingAssertion,
    "c2pa.usage": UsageAssertion,
}

__all__ = [
    "Assertion",
    "AIGeneratedAssertion",
    "TrainingAssertion",
    "UsageAssertion",
    "ASSERTION_REGISTRY",
]
