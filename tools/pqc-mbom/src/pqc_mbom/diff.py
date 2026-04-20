"""Diff two MBOMs - useful for auditing model updates / fine-tunes."""

from __future__ import annotations

from dataclasses import dataclass

from pqc_mbom.component import ModelComponent
from pqc_mbom.mbom import MBOM


@dataclass(frozen=True)
class MBOMDiff:
    added: list[ModelComponent]
    removed: list[ModelComponent]
    changed: list[tuple[ModelComponent, ModelComponent]]  # (old, new) same id different hash

    @property
    def is_empty(self) -> bool:
        """True iff the two MBOMs describe the same component set with identical hashes."""
        return not self.added and not self.removed and not self.changed


def diff_mboms(old: MBOM, new: MBOM) -> MBOMDiff:
    old_by_id = {c.component_id: c for c in old.components}
    new_by_id = {c.component_id: c for c in new.components}

    added = [c for cid, c in new_by_id.items() if cid not in old_by_id]
    removed = [c for cid, c in old_by_id.items() if cid not in new_by_id]
    changed: list[tuple[ModelComponent, ModelComponent]] = []
    for cid, old_c in old_by_id.items():
        if cid in new_by_id and old_c.hash() != new_by_id[cid].hash():
            changed.append((old_c, new_by_id[cid]))
    return MBOMDiff(added=added, removed=removed, changed=changed)
