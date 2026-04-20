"""SHA3-256 Merkle tree over a list of leaf hashes."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from pqc_training_data.errors import (
    EmptyTreeError,
    InclusionProofError,
    IndexOutOfRangeError,
)
from pqc_training_data.record import RecordHash


def _pair_hash(left: bytes, right: bytes) -> bytes:
    """Internal-node hash: SHA3-256(0x01 || left || right).

    The 0x01 prefix domain-separates internal from leaf hashes
    (leaves are prefixed 0x00 upstream).
    """
    return hashlib.sha3_256(b"\x01" + left + right).digest()


def _leaf_hash_bytes(leaf_bytes: bytes) -> bytes:
    """Wrap a leaf hash with 0x00 domain separator."""
    return hashlib.sha3_256(b"\x00" + leaf_bytes).digest()


@dataclass(frozen=True)
class InclusionProof:
    """Proof that a leaf is in a Merkle tree.

    `siblings` is the list of sibling hashes walking from leaf to root.
    `directions` are 'L' or 'R' indicating which side each sibling is on.
    `index` is the 0-based leaf index; `tree_size` is total leaf count.
    """

    leaf_hash: str            # hex (the ORIGINAL leaf_hash, BEFORE 0x00 prefix)
    index: int
    tree_size: int
    root: str                 # hex
    siblings: list[str]       # hex, each a sibling hash (the raw node hash)
    directions: list[str]     # 'L' or 'R' (whether sibling is on left or right of our path)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MerkleTree:
    """SHA3-256 Merkle tree. Works for any number of leaves (>= 1).

    For odd levels, the last node is promoted (duplicated) - standard
    RFC6962-style handling. Leaves are SHA3-256(0x00 || leaf_value);
    internal nodes are SHA3-256(0x01 || left || right).
    """

    leaves: list[RecordHash] = field(default_factory=list)

    def add(self, leaf_hash: RecordHash) -> None:
        self.leaves.append(leaf_hash)

    def add_many(self, leaf_hashes: list[RecordHash]) -> None:
        self.leaves.extend(leaf_hashes)

    @property
    def size(self) -> int:
        return len(self.leaves)

    def root(self) -> str:
        """Compute the Merkle root hex. Raises EmptyTreeError if no leaves."""
        if not self.leaves:
            raise EmptyTreeError("cannot compute root of empty tree")

        level: list[bytes] = [_leaf_hash_bytes(leaf.bytes) for leaf in self.leaves]
        while len(level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(_pair_hash(left, right))
            level = next_level
        return level[0].hex()

    def inclusion_proof(self, index: int) -> InclusionProof:
        """Generate an inclusion proof for the leaf at `index`."""
        if not self.leaves:
            raise EmptyTreeError("empty tree has no proofs")
        if index < 0 or index >= len(self.leaves):
            raise IndexOutOfRangeError(
                f"index {index} out of range [0, {len(self.leaves) - 1}]"
            )

        level: list[bytes] = [_leaf_hash_bytes(leaf.bytes) for leaf in self.leaves]
        siblings: list[str] = []
        directions: list[str] = []
        idx = index

        while len(level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(_pair_hash(left, right))

            # Which side is our sibling on?
            sib_index = idx ^ 1  # XOR 1 flips bottom bit
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

        return InclusionProof(
            leaf_hash=self.leaves[index].hex,
            index=index,
            tree_size=self.size,
            root=level[0].hex(),
            siblings=siblings,
            directions=directions,
        )

    @staticmethod
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
                raise InclusionProofError(f"invalid direction: {direction}")
        return current.hex() == proof.root
