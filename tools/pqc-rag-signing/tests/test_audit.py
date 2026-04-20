"""Tests for RAGAuditLog."""

from __future__ import annotations

import json

from pqc_rag_signing import RAGAuditLog


def test_log_sign_creates_entry(audit_log: RAGAuditLog) -> None:
    audit_log.log_sign(
        corpus_id="corpus-1",
        chunk_id="chunk-1",
        signer_did="did:pqaid:abc",
        algorithm="ML-DSA-65",
    )
    assert len(audit_log) == 1
    entries = audit_log.entries()
    assert entries[0].operation == "sign_chunk"
    assert entries[0].chunk_id == "chunk-1"
    assert entries[0].signer_did == "did:pqaid:abc"
    assert entries[0].verified is True


def test_log_verify_records_result(audit_log: RAGAuditLog) -> None:
    audit_log.log_verify(
        chunk_id="chunk-1",
        signer_did="did:pqaid:abc",
        algorithm="ML-DSA-65",
        verified=False,
        details="bad signature",
    )
    entries = audit_log.entries()
    assert entries[0].operation == "verify_chunk"
    assert entries[0].verified is False
    assert entries[0].details == "bad signature"


def test_log_retrieval_aggregates(audit_log: RAGAuditLog) -> None:
    audit_log.log_retrieval(
        query_hash="a" * 64,
        verified_count=4,
        failed_count=1,
    )
    entries = audit_log.entries()
    assert entries[0].operation == "retrieve"
    assert entries[0].verified is False
    assert entries[0].query_hash == "a" * 64
    assert "4 verified, 1 failed" in (entries[0].details or "")


def test_entries_filter_by_operation(audit_log: RAGAuditLog) -> None:
    audit_log.log_sign("c1", "k1", "did:x", "ML-DSA-65")
    audit_log.log_verify("k1", "did:x", "ML-DSA-65", verified=True)
    audit_log.log_retrieval("qh", 1, 0)
    signs = audit_log.entries(operation="sign_chunk")
    verifies = audit_log.entries(operation="verify_chunk")
    retrievals = audit_log.entries(operation="retrieve")
    assert len(signs) == 1 and signs[0].operation == "sign_chunk"
    assert len(verifies) == 1 and verifies[0].operation == "verify_chunk"
    assert len(retrievals) == 1 and retrievals[0].operation == "retrieve"


def test_entries_filter_by_signer(audit_log: RAGAuditLog) -> None:
    audit_log.log_sign("c1", "k1", "did:alice", "ML-DSA-65")
    audit_log.log_sign("c1", "k2", "did:bob", "ML-DSA-65")
    audit_log.log_sign("c1", "k3", "did:alice", "ML-DSA-65")
    alice_entries = audit_log.entries(signer_did="did:alice")
    assert len(alice_entries) == 2
    assert all(e.signer_did == "did:alice" for e in alice_entries)


def test_export_json_valid(audit_log: RAGAuditLog) -> None:
    audit_log.log_sign("c1", "k1", "did:x", "ML-DSA-65")
    audit_log.log_verify("k1", "did:x", "ML-DSA-65", verified=True)
    js = audit_log.export_json()
    parsed = json.loads(js)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["operation"] == "sign_chunk"


def test_max_entries_respected() -> None:
    log = RAGAuditLog(max_entries=3)
    for i in range(5):
        log.log_sign("c1", f"k{i}", "did:x", "ML-DSA-65")
    assert len(log) == 3
    # Oldest entries dropped, newest kept
    ids = [e.chunk_id for e in log.entries()]
    assert "k0" not in ids
    assert "k4" in ids
