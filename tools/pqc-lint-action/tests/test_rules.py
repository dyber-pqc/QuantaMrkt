"""Tests for the rule catalog."""

from __future__ import annotations

from pqc_lint.rules import RULES, get_rules_for_language


def test_all_rule_ids_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_get_rules_for_language_python():
    rules = get_rules_for_language("python")
    ids = {r.id for r in rules}
    # signatures, kex, encryption, hashes — all apply to python
    assert "PQC001" in ids
    assert "PQC002" in ids
    assert "PQC003" in ids
    assert "PQC301" in ids
    assert "PQC302" in ids


def test_get_rules_for_language_go():
    rules = get_rules_for_language("go")
    ids = {r.id for r in rules}
    assert "PQC001" in ids
    assert "PQC002" in ids
    # DSA is python/java only
    assert "PQC004" not in ids


def test_rule_suggestion_non_empty_for_known_primitives():
    for rule in RULES:
        assert rule.suggestion != "", f"rule {rule.id} ({rule.classical_primitive}) has no suggestion"
