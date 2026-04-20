"""LoadPolicy - decide whether a signed program may be loaded."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pqc_ebpf_attestation.errors import PolicyDeniedError, UntrustedSignerError
from pqc_ebpf_attestation.program import BPFProgramType
from pqc_ebpf_attestation.signer import BPFVerifier, SignedBPFProgram


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class PolicyRule:
    """One rule in a LoadPolicy."""

    program_types: tuple[BPFProgramType, ...]  # which types the rule applies to
    allowed_signers: frozenset[str]  # DIDs permitted to load these types
    require_signature: bool = True
    max_bytecode_size: int = 2 * 1024 * 1024  # 2 MB default cap

    def applies_to(self, program_type: BPFProgramType) -> bool:
        return program_type in self.program_types


@dataclass
class LoadPolicy:
    """An ordered list of rules. First matching rule wins.

    Default (with no rules) denies everything.
    """

    rules: list[PolicyRule] = field(default_factory=list)
    default_decision: PolicyDecision = PolicyDecision.DENY

    def add_rule(self, rule: PolicyRule) -> LoadPolicy:
        self.rules.append(rule)
        return self

    def evaluate(self, signed: SignedBPFProgram) -> tuple[PolicyDecision, str]:
        """Decide whether this signed program may load. Returns (decision, reason)."""
        # Find first matching rule
        matching: PolicyRule | None = None
        for rule in self.rules:
            if rule.applies_to(signed.program.metadata.program_type):
                matching = rule
                break

        if matching is None:
            return (
                self.default_decision,
                f"no rule for program_type={signed.program.metadata.program_type.value}",
            )

        # Size check
        if signed.program.bytecode_size > matching.max_bytecode_size:
            return (
                PolicyDecision.DENY,
                f"bytecode size {signed.program.bytecode_size} exceeds cap "
                f"{matching.max_bytecode_size}",
            )

        # Signature check
        if matching.require_signature:
            result = BPFVerifier.verify(signed)
            if not result.valid:
                return PolicyDecision.DENY, result.error or "signature invalid"

        # Signer allow-list
        if matching.allowed_signers and signed.signer_did not in matching.allowed_signers:
            return (
                PolicyDecision.DENY,
                f"signer {signed.signer_did} not in allow-list",
            )

        return PolicyDecision.ALLOW, "policy rule matched; all checks passed"

    def enforce(self, signed: SignedBPFProgram) -> None:
        """Raise if the program would be denied."""
        decision, reason = self.evaluate(signed)
        if decision == PolicyDecision.DENY:
            # Distinguish untrusted signer vs general deny
            if "not in allow-list" in reason:
                raise UntrustedSignerError(reason)
            raise PolicyDeniedError(reason)
