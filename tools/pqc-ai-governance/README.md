# PQC AI Governance

![PQC Native](https://img.shields.io/badge/PQC-Native-blue)
![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-green)
![BFT](https://img.shields.io/badge/Byzantine%20Fault%20Tolerant-PBFT%20style-purple)
![License](https://img.shields.io/badge/License-Apache%202.0-orange)
![Version](https://img.shields.io/badge/version-0.1.0-lightgrey)

**A quantum-resistant DAO for enterprise AI governance.** Distributed governance nodes reach cryptographic agreement on which AI models may run, which agents may act, and which policies are in force - every proposal, every vote, and every consensus result carries an **ML-DSA** (FIPS 204) signature. When an agent tries to load a model, every node can independently verify the authorization is legitimate and quantum-unforgeable.

## The Problem

Large enterprises run fleets of AI agents across business units. Today, whether an agent is allowed to load a particular model, call a particular tool, or delegate to a sub-agent is enforced by **classical PKI certificates** - RSA and ECDSA signatures that will be **retroactively forgeable** once a cryptographically relevant quantum computer exists. A forged authorization issued in 2027 still authorizes the agent in 2045, long after the underlying signature scheme has fallen. Governance decisions must outlive the crypto they were originally signed with, or they are not governance decisions at all.

Classical governance also typically relies on a single signing authority (a KMS, a root CA). Compromise that authority and the entire AI stack is silently re-authorized by the attacker.

## The Solution

- **Byzantine-fault-tolerant consensus.** A `ConsensusRound` aggregates signed votes from an allow-listed set of `GovernanceNode`s and decides pass/reject under a configurable `QuorumPolicy` (default: PBFT-style 2/3 participation and 2/3 approval).
- **Every artifact is ML-DSA signed.** Proposals are signed by the proposer's node. Votes are signed by the voter's node. The finalised `ConsensusResult` is signed by the coordinating node. Auditors can verify any of the three forever.
- **Byzantine double-voting is caught at tally time.** `VoteTally` refuses to silently absorb conflicting votes from the same DID and raises `ByzantineDetectedError` with an unambiguous audit record.
- **Authorization chains.** `AuthorizationChain` walks the passed grants for a subject (a model DID, an agent DID) and applies `AUTHORIZE_* -> REVOKE_*` semantics to answer "is this subject currently authorized?".
- **No single point of trust.** No KMS, no root CA, no magic signing service. Authority lives in a quorum of node keys - quantum-safe from day one.

## Installation

```bash
pip install pqc-ai-governance
```

Development:

```bash
pip install -e ".[dev]"
pytest
```

## Quick Start

```python
from quantumshield.identity.agent import AgentIdentity
from pqc_ai_governance import (
    AuthorizationChain, AuthorizationGrant,
    ConsensusRound, GovernanceNode, GovernanceProposal,
    NodeRegistry, ProposalKind, QuorumPolicy, VoteDecision,
)

# 1. Stand up five governance nodes (each with a PQC identity).
alice = GovernanceNode(identity=AgentIdentity.create("alice"), name="alice", weight=1)
bob   = GovernanceNode(identity=AgentIdentity.create("bob"),   name="bob",   weight=1)
carol = GovernanceNode(identity=AgentIdentity.create("carol"), name="carol", weight=1)
dave  = GovernanceNode(identity=AgentIdentity.create("dave"),  name="dave",  weight=2)
eve   = GovernanceNode(identity=AgentIdentity.create("eve"),   name="eve",   weight=1)

registry = NodeRegistry()
for n in (alice, bob, carol, dave, eve):
    registry.register(n)

# 2. Alice proposes authorizing a medical-AI model.
proposal = GovernanceProposal.create(
    kind=ProposalKind.AUTHORIZE_MODEL,
    subject_id="did:pqaid:medical-ai-v2",
    title="Authorize medical-ai-v2 for production",
    proposer_did=alice.did,
    parameters={"environment": "prod", "max_rate_qps": 50},
)
alice.sign_proposal(proposal)

# 3. Nodes vote.
rnd = ConsensusRound(proposal=proposal, registry=registry, policy=QuorumPolicy())
for voter in (alice, bob, carol, dave):
    rnd.cast(voter.cast_vote(proposal, VoteDecision.APPROVE))
rnd.cast(eve.cast_vote(proposal, VoteDecision.ABSTAIN))

# 4. Finalize. The result is ML-DSA signed by the coordinator.
result = rnd.finalize(coordinator=alice)
assert result.decision == "passed"
assert ConsensusRound.verify_result(result)

# 5. Bind the passed result into an authorization chain.
chain = AuthorizationChain(subject_id=proposal.subject_id)
chain.add(AuthorizationGrant(
    subject_id=proposal.subject_id,
    kind=proposal.kind,
    result=result,
))
assert chain.is_authorized(ProposalKind.AUTHORIZE_MODEL)
```

## Architecture

```
    Proposer node                Every other governance node
    -------------                ---------------------------
         |                                  |
         | GovernanceProposal.create(kind,  |
         |   subject_id, parameters, ...)   |
         |                                  |
         | sign_proposal()                  |
         |   ML-DSA / SHA3-256              |
         |                                  |
         +------------> broadcast --------->+
                                            |
                                            | verify_proposal()
                                            | cast_vote(APPROVE |
                                            |           REJECT  |
                                            |           ABSTAIN)
                                            |   ML-DSA / SHA3-256
                                            v
                         +-------------------------------------+
                         |           ConsensusRound            |
                         |                                     |
                         |  VoteTally                          |
                         |   - verify each signature           |
                         |   - reject non-member voters        |
                         |   - reject wrong proposal_hash      |
                         |   - Byzantine check: same DID       |
                         |     voting two different decisions  |
                         |     -> ByzantineDetectedError       |
                         |                                     |
                         |  QuorumPolicy                       |
                         |   - min_participation_fraction      |
                         |     (default 2/3 of total_weight)   |
                         |   - min_approval_fraction           |
                         |     (default 2/3 of non-abstain)    |
                         |                                     |
                         |  finalize(coordinator)              |
                         +------------------+------------------+
                                            |
                                            v
                         +-------------------------------------+
                         |          ConsensusResult            |
                         |   proposal_id, proposal_hash,       |
                         |   decision (passed | rejected),     |
                         |   reason, approve/reject/abstain    |
                         |   weights, total_weight,            |
                         |   included_vote_ids[], decided_at   |
                         |                                     |
                         |   +  ML-DSA signature by coordinator|
                         +------------------+------------------+
                                            |
                                            v
                               AuthorizationChain(subject_id)
                                  .add(AuthorizationGrant(result))
                                  .is_authorized(AUTHORIZE_MODEL)
```

## ProposalKind Reference

| Kind | Meaning |
|---|---|
| `AUTHORIZE_MODEL` | Grant a specific AI model permission to run under the given scope. |
| `REVOKE_MODEL` | Withdraw a previously granted model authorization. |
| `AUTHORIZE_AGENT` | Grant a specific agent permission to act. |
| `REVOKE_AGENT` | Withdraw agent authorization. |
| `UPDATE_POLICY` | Change a runtime governance policy (rate limits, scopes, feature flags). |
| `ADD_NODE` | Admit a new node into the `NodeRegistry`. |
| `REMOVE_NODE` | Evict an existing governance node. |
| `EMERGENCY_FREEZE` | Halt all agent action immediately (break-glass). |
| `DELEGATION` | Allow agent X to delegate authority to agent Y. |

## Cryptography

| Layer | Primitive | Notes |
|---|---|---|
| Signatures | **ML-DSA-65** (FIPS 204, a.k.a. CRYSTALS-Dilithium) | Default for every proposal, vote, and consensus result via `quantumshield`. Swap algorithm via `AgentIdentity.create(algorithm=...)`. |
| Canonical hashing | **SHA3-256** over RFC-8785-style canonical JSON | Used to bind signatures to a stable bytestring (alphabetised keys, no whitespace). |
| Identity | `did:pqaid:<SHA3-256(public_key)>` | From `quantumshield.identity.agent.AgentIdentity`. |

## Quorum Policy

Default `QuorumPolicy` is PBFT-style:

| Setting | Default | Meaning |
|---|---|---|
| `min_participation_fraction` | `2/3` | `(approve+reject+abstain) / total_weight` must meet this. |
| `min_approval_fraction` | `2/3` | `approve / (approve+reject)` must meet this. Abstains are ignored for the ratio but count for participation. |

A 5-node cluster with weights `1/1/1/2/1` (total = 6) therefore needs at least 4 weight units cast and at least 2/3 approval among non-abstain voters to pass.

## Threat Model

| Threat | Mitigation |
|---|---|
| **Proposal forgery** (attacker crafts a proposal claiming to be from node A) | Only A's private key produces a valid ML-DSA signature over A's canonical proposal bytes. `GovernanceNode.verify_proposal()` checks it. |
| **Proposal tampering in transit** (change `parameters` after signing) | `proposal_hash()` recomputes over canonical JSON; any edit invalidates the signature. |
| **Vote forgery** (attacker fabricates a vote from node B) | `GovernanceNode.verify_vote()` rejects anything whose ML-DSA signature does not verify against B's declared public key. |
| **Double-voting / Byzantine flip-flop** (node C votes APPROVE then later REJECT) | `VoteTally` raises `ByzantineDetectedError` on conflicting decisions. Identical repeat votes are idempotent. |
| **Cross-proposal replay** (replay a valid vote for proposal P against proposal Q) | Every vote binds both `proposal_id` *and* `proposal_hash`. Tally rejects hash mismatches. |
| **Non-member injection** (a rogue node signs a valid-looking vote) | Votes from DIDs absent from `NodeRegistry` are recorded as `"non-member voter"` and do not affect weights. |
| **Result forgery** (attacker hands auditor a fake "passed" result) | `ConsensusResult` is signed by the coordinator over canonical bytes covering every weight and every included vote id. `ConsensusRound.verify_result()` checks it. |
| **Harvest-now-decrypt-later** (adversary records today, breaks RSA/ECDSA in a future quantum computer) | Every signature is ML-DSA (FIPS 204); post-quantum secure against known attacks. |
| **Stale authorization** (old AUTHORIZE_MODEL grant lingers after policy change) | `AuthorizationChain.is_authorized()` honours subsequent passed `REVOKE_*` grants; operators issue a revocation proposal instead of mutating history. |

## API Reference

### `GovernanceNode`

Wraps a `quantumshield.identity.agent.AgentIdentity`. Produces signed proposals and signed votes.

| Member | Description |
|---|---|
| `identity`, `name`, `weight` | The underlying PQ-AID identity, display name, and voting weight. |
| `did` | Derived DID (read-only). |
| `sign_proposal(proposal)` | Populate signer/algorithm/signature/public_key on the proposal and return it. |
| `cast_vote(proposal, decision, rationale="")` | Create, sign, and return a `SignedVote`. |
| `GovernanceNode.verify_proposal(proposal)` | Static; ML-DSA check over canonical bytes. |
| `GovernanceNode.verify_vote(signed)` | Static; ML-DSA check over the vote's canonical bytes. |

### `NodeRegistry`

Allow-list of governance nodes keyed by DID.

| Method | Description |
|---|---|
| `register(node)` / `remove(did)` | Add/remove membership. |
| `get(did)` | Look up; raises `UnknownNodeError` if absent. |
| `is_member(did)` / `total_weight()` / `list_dids()` / `len(...)` | Queries. |

### `GovernanceProposal`

| Field | Description |
|---|---|
| `proposal_id`, `kind`, `subject_id`, `title`, `description`, `proposer_did`, `parameters`, `created_at`, `expires_at`, `status` | Proposal body. |
| `signer_did`, `algorithm`, `signature`, `public_key` | Signature envelope. |

| Method | Description |
|---|---|
| `GovernanceProposal.create(kind, subject_id, title, proposer_did, ...)` | Build with generated id and TTL. |
| `canonical_bytes()` / `proposal_hash()` | Deterministic canonical JSON / SHA3-256. |
| `is_expired()` | TTL check. |
| `to_dict()` / `from_dict()` | JSON-safe round-trip. |

### `Vote` / `SignedVote`

`Vote` binds a `decision` to both `proposal_id` and `proposal_hash`. `SignedVote` is the envelope with ML-DSA signature.

### `VoteTally`

Aggregates `SignedVote` objects. Rejects (and records) votes with: wrong proposal hash, wrong proposal id, invalid signature, non-member voter. Raises `ByzantineDetectedError` on conflicting repeat decisions from the same DID.

| Field | Description |
|---|---|
| `approve_weight` / `reject_weight` / `abstain_weight` | Running totals. |
| `valid_votes` / `invalid_votes` | Accepted and rejected entries (with reason). |
| `total_cast_weight()` / `to_dict()` | Views. |

### `ConsensusRound`

| Method | Description |
|---|---|
| `ConsensusRound(proposal, registry, policy=QuorumPolicy())` | Construct. |
| `cast(signed_vote)` | Record a vote; raises `ProposalExpiredError` if TTL elapsed. |
| `finalize(coordinator)` | Decide, then ML-DSA sign the `ConsensusResult` with the coordinator's identity. |
| `ConsensusRound.verify_result(result)` | Static; verify the coordinator's signature. |

### `QuorumPolicy`

Fractions of total voting weight: `min_participation_fraction` and `min_approval_fraction` (abstains do not count in the approval ratio).

### `ConsensusResult`

Signed outcome. Fields: `proposal_id`, `proposal_hash`, `decision` (`"passed"|"rejected"`), `reason`, `approve_weight`, `reject_weight`, `abstain_weight`, `total_weight`, `included_vote_ids`, `decided_at`, plus signature envelope. Provides `canonical_bytes()`, `to_dict()`, `to_json()`.

### `AuthorizationChain` / `AuthorizationGrant`

`AuthorizationChain` is an ordered list of `AuthorizationGrant`s for a single subject. `is_authorized(kind)` returns `True` iff the most recent passed grant for the relevant `AUTHORIZE_*` is not superseded by a later passed `REVOKE_*` (model and agent).

### `GovernanceAuditLog`

In-memory append-only log. Typed helpers for `log_proposal_created`, `log_vote_cast`, `log_consensus_reached`, `log_byzantine_detected`, `log_node_added`, `log_node_removed`, `log_authorization_granted`, `log_authorization_revoked`. Filter via `entries(operation=..., proposal_id=..., actor_did=...)`. Exports to JSON.

### Exceptions

| Exception | When |
|---|---|
| `GovernanceError` | Base class. |
| `InvalidProposalError` | Structurally invalid proposal or bad signature. |
| `InvalidVoteError` | Structurally invalid vote or bad signature. |
| `InsufficientQuorumError` | Participation threshold not met (when raised). |
| `ConsensusFailedError` | Round cannot reach a decision. |
| `UnknownNodeError` | DID absent from `NodeRegistry`. |
| `ByzantineDetectedError` | Conflicting repeat votes from a single DID. |
| `ProposalExpiredError` | Vote cast after the proposal's TTL. |

## Why PQC for AI Governance?

Enterprise AI governance roots are trust anchors with a **multi-decade** shelf life. A model authorization issued today still authorizes the model in 2045. An agent delegation chain signed in 2027 still matters when that agent acts on a regulated dataset in 2040. The moment a classical signature scheme falls to a cryptographically relevant quantum computer, every governance decision ever signed with that scheme becomes retroactively forgeable - a "harvest-now, re-authorize-later" attack against your entire AI fleet.

Post-quantum signatures are the only way to make an AI governance audit trail that still means something after Q-day.

## Examples

See the `examples/` directory:

- **`model_authorization.py`** - five nodes approve a medical AI model; signed result binds into an `AuthorizationChain`.
- **`byzantine_detection.py`** - one node submits conflicting votes; `VoteTally` raises `ByzantineDetectedError`; the audit log records the violation.
- **`emergency_freeze.py`** - unanimous EMERGENCY_FREEZE; signed `ConsensusResult` produced and verified.

Run them:

```bash
python examples/model_authorization.py
python examples/byzantine_detection.py
python examples/emergency_freeze.py
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/ examples/
```

## Related

Part of the [QuantaMrkt](https://quantamrkt.com) post-quantum tooling registry. See also:

- **QuantumShield** - the PQC toolkit (`AgentIdentity`, `SignatureAlgorithm`, `sign/verify`).
- **PQC Federated Learning** - signed gradient updates and aggregation proofs.
- **PQC Audit Log FS** - rotating, Merkle-anchored on-disk audit segments.
- **PQC Reasoning Ledger** - ML-DSA signed agent reasoning traces.
- **PQC RAG Signing** - sign retrieval chunks with ML-DSA.

## License

Apache License 2.0. See [LICENSE](LICENSE).
