"""Access policies - which app bundles / artifact kinds may be read by whom."""

from __future__ import annotations

from dataclasses import dataclass, field

from pqc_enclave_sdk.artifact import ArtifactKind, ArtifactMetadata
from pqc_enclave_sdk.errors import PolicyViolationError


@dataclass
class ArtifactPolicy:
    """Policy rule for a single artifact kind."""

    kind: ArtifactKind
    allowed_bundle_ids: frozenset[str]
    require_biometric: bool = False
    max_uses_per_hour: int = 0


@dataclass
class AccessPolicy:
    """Collection of per-kind policies."""

    rules: dict[ArtifactKind, ArtifactPolicy] = field(default_factory=dict)

    def add(self, rule: ArtifactPolicy) -> AccessPolicy:
        self.rules[rule.kind] = rule
        return self

    def check(self, artifact_meta: ArtifactMetadata, caller_bundle_id: str) -> None:
        rule = self.rules.get(artifact_meta.kind)
        if rule is None:
            return
        if (
            rule.allowed_bundle_ids
            and caller_bundle_id not in rule.allowed_bundle_ids
        ):
            raise PolicyViolationError(
                f"caller {caller_bundle_id} not allowed to read "
                f"{artifact_meta.kind.value}"
            )
