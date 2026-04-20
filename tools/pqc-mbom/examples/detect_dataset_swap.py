"""Detect a training-dataset swap between two MBOM versions.

Simulates an attacker (or careless pipeline) that replaces a training-data
component in-place: same component_id, different content_hash. The MBOM diff
flags it, and any tampering with the *signed* MBOM fails verification.
"""

from __future__ import annotations

import hashlib

from quantumshield.identity.agent import AgentIdentity

from pqc_mbom import (
    ComponentType,
    MBOM,
    MBOMBuilder,
    MBOMSigner,
    MBOMVerifier,
    diff_mboms,
)


def _h(label: str) -> str:
    return hashlib.sha3_256(label.encode()).hexdigest()


def main() -> None:
    identity = AgentIdentity.create("publisher")
    attacker_identity = AgentIdentity.create("attacker")

    # v1 - published
    v1 = (
        MBOMBuilder("MyModel", "1.0.0", supplier="Acme")
        .add_base_architecture("transformer-decoder", version="1", content_hash=_h("arch"))
        .add_training_data("trusted-corpus", content_hash=_h("good-dataset"), content_size=10**9)
        .add_weights("model.safetensors", content_hash=_h("weights"), content_size=8 * 10**9)
        .build()
    )
    MBOMSigner(identity).sign(v1)
    v1_json = v1.to_json()

    # v2 - same component_id for training data, different hash (a swap).
    v2 = MBOM.from_json(v1_json)
    v2.model_version = "1.0.1"
    for c in v2.components:
        if c.component_type == ComponentType.TRAINING_DATA:
            c.content_hash = _h("poisoned-dataset")
    v2.recompute_root()
    MBOMSigner(identity).sign(v2)

    diff = diff_mboms(v1, v2)
    print("Diff v1 -> v2:")
    print(f"  added:   {[c.name for c in diff.added]}")
    print(f"  removed: {[c.name for c in diff.removed]}")
    print(f"  changed: {[(o.name, o.content_hash[:8], '->', n.content_hash[:8]) for o, n in diff.changed]}")
    assert diff.changed, "dataset swap should be detected as a change"
    assert diff.changed[0][0].component_type == ComponentType.TRAINING_DATA

    # Both v1 and v2 verify on their own - they are each legitimately signed.
    assert MBOMVerifier.verify(v1).valid
    assert MBOMVerifier.verify(v2).valid

    # Now the attacker scenario: tamper with a *signed* MBOM without re-signing.
    tampered = MBOM.from_json(v1_json)
    for c in tampered.components:
        if c.component_type == ComponentType.TRAINING_DATA:
            c.content_hash = _h("poisoned-dataset")
    # Does NOT recompute root, does NOT re-sign.
    result = MBOMVerifier.verify(tampered)
    print("\nUnsigned tampering attempt (same signer, no re-sign):")
    print(f"  valid={result.valid} error={result.error}")
    assert not result.valid

    # Adversarial re-sign by a *different* identity still verifies
    # cryptographically, but the signer_did reveals the swap - trust policy
    # layer should reject unknown signers.
    forged = MBOM.from_json(v1_json)
    for c in forged.components:
        if c.component_type == ComponentType.TRAINING_DATA:
            c.content_hash = _h("poisoned-dataset")
    MBOMSigner(attacker_identity).sign(forged)
    result = MBOMVerifier.verify(forged)
    print("\nForged MBOM re-signed by attacker:")
    print(f"  valid={result.valid} signer_did={result.signer_did}")
    print(f"  original signer was {identity.did}")
    print("  -> trust-policy layer rejects: signer_did not in allow-list")


if __name__ == "__main__":
    main()
