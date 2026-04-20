"""SHA3-256 Merkle tree with domain-separated leaves/internal nodes.

Leaves:        SHA3-256(0x00 || leaf_value)
Internal node: SHA3-256(0x01 || left || right)

For odd levels, the last node is promoted (duplicated) - RFC6962-style.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

from pqc_reasoning_ledger.errors import ReasoningLedgerError


def _pair_hash(left: bytes, right: bytes) -> bytes:
    """Internal-node hash: SHA3-256(0x01 || left || right)."""
    return hashlib.sha3_256(b"\x01" + left + right).digest()


def _leaf_hash_bytes(leaf_bytes: bytes) -> bytes:
    """Leaf-node hash: SHA3-256(0x00 || leaf_bytes)."""
    return hashlib.sha3_256(b"\x00" + leaf_bytes).digest()


@dataclass(frozen=True)
class InclusionProof:
    """Proof that a leaf is in a Merkle tree.

    `siblings` is the list of sibling hashes walking from leaf to root.
    `directions` are 'L' or 'R' indicating which side each sibling is on.
    `index` is the 0-based leaf index; `tree_size` is total leaf count.
    """

    leaf_hash: str              # hex (the ORIGINAL leaf hash, BEFORE 0x00 prefix)
    index: int
    tree_size: int
    root: str                   # hex
    siblings: list[str]         # hex, each a sibling node hash
    directions: list[str]       # 'L' or 'R'

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InclusionProof:
        return cls(**data)


def compute_merkle_root(leaves: list[str]) -> str:
    """Compute the SHA3-256 Merkle root over a list of hex-encoded leaf hashes.

    Raises ReasoningLedgerError if `leaves` is empty.
    """
    if not leaves:
        raise ReasoningLedgerError("cannot compute root of empty tree")

    level: list[bytes] = [_leaf_hash_bytes(bytes.fromhex(h)) for h in leaves]
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(_pair_hash(left, right))
        level = next_level
    return level[0].hex()


def build_proof(
    leaves: list[str], index: int, root: str | None = None
) -> InclusionProof:
    """Build an inclusion proof for `leaves[index]`.

    Raises ReasoningLedgerError if leaves is empty or index out of range.
    If `root` is provided, it is stored on the proof; otherwise it is
    re-computed from `leaves`.
    """
    if not leaves:
        raise ReasoningLedgerError("cannot build proof for empty tree")
    if index < 0 or index >= len(leaves):
        raise ReasoningLedgerError(
            f"index {index} out of range [0, {len(leaves) - 1}]"
        )

    level: list[bytes] = [_leaf_hash_bytes(bytes.fromhex(h)) for h in leaves]
    siblings: list[str] = []
    directions: list[str] = []
    idx = index

    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(_pair_hash(left, right))

        sib_index = idx ^ 1
        if sib_index >= len(level):
            # odd-node case: sibling is a duplicate of ourselves
            sib = level[idx]
            direction = "L" if idx % 2 == 1 else "R"
        else:
            sib = level[sib_index]
            direction = "L" if sib_index < idx else "R"
        siblings.append(sib.hex())
        directions.append(direction)

        idx //= 2
        level = next_level

    computed_root = level[0].hex()
    return InclusionProof(
        leaf_hash=leaves[index],
        index=index,
        tree_size=len(leaves),
        root=root if root is not None else computed_root,
        siblings=siblings,
        directions=directions,
    )


def verify_inclusion(proof: InclusionProof) -> bool:
    """Independently verify an inclusion proof. Returns True iff valid."""
    current = _leaf_hash_bytes(bytes.fromhex(proof.leaf_hash))
    for sib_hex, direction in zip(proof.siblings, proof.directions):
        sib = bytes.fromhex(sib_hex)
        if direction == "L":
            current = _pair_hash(sib, current)
        elif direction == "R":
            current = _pair_hash(current, sib)
        else:
            return False
    return current.hex() == proof.root
