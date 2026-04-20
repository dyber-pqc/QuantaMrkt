"""Provenance chain -- link manifests across edits/derivations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from pqc_content_provenance.errors import ChainBrokenError
from pqc_content_provenance.manifest import ContentManifest
from pqc_content_provenance.signer import ManifestSigner


@dataclass
class ProvenanceLink:
    """One link in a provenance chain: (manifest, verification_result)."""

    manifest: ContentManifest


@dataclass
class ProvenanceChain:
    """An ordered chain of ContentManifests where each links to the previous."""

    links: list[ProvenanceLink] = field(default_factory=list)

    def add(self, manifest: ContentManifest) -> None:
        if self.links:
            prev = self.links[-1].manifest
            if manifest.previous_manifest_id != prev.manifest_id:
                raise ChainBrokenError(
                    f"manifest {manifest.manifest_id} previous_manifest_id "
                    f"({manifest.previous_manifest_id}) does not match "
                    f"prior manifest id ({prev.manifest_id})"
                )
        self.links.append(ProvenanceLink(manifest=manifest))

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify every signature in the chain + every link."""
        errors: list[str] = []
        prev_id: str | None = None
        for link in self.links:
            m = link.manifest
            if prev_id is not None and m.previous_manifest_id != prev_id:
                errors.append(f"link break at {m.manifest_id}: expected prev {prev_id}")
            result = ManifestSigner.verify(m)
            if not result.valid:
                errors.append(f"signature invalid at {m.manifest_id}: {result.error}")
            prev_id = m.manifest_id
        return len(errors) == 0, errors

    def to_dicts(self) -> list[dict]:
        return [link.manifest.to_dict() for link in self.links]

    @classmethod
    def from_dicts(cls, items: Iterable[dict]) -> ProvenanceChain:
        chain = cls()
        for item in items:
            chain.links.append(ProvenanceLink(manifest=ContentManifest.from_dict(item)))
        return chain
