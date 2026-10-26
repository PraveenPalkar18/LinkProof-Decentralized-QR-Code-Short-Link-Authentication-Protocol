"""Test suite for the LinkProof evaluation engine, trust store, and verifier."""
import pytest
from core.crypto import (
    compute_public_key_fingerprint,
    export_public_key_pem,
    generate_key_pair,
)
from core.record import build_record_data, create_signed_payload
from core.trust_store import evaluate_linkproof_payload
from models.database import add_trusted_key, init_db


@pytest.fixture(autouse=True)
def setup_memory_db():
    """Initialize SQLite database before each test run and isolate tables."""
    from models.database import get_db_connection
    init_db(":memory:")
    with get_db_connection(":memory:") as conn:
        conn.execute("DELETE FROM verification_history")
        conn.execute("DELETE FROM trusted_keys")
        conn.commit()


def test_legitimate_signed_qr_record_verifies():
    """Scenario 1: Legitimate signed QR record with trusted issuer verifies successfully."""
    priv, pub = generate_key_pair()
    pub_pem = export_public_key_pem(pub)
    fp = compute_public_key_fingerprint(pub)

    # Trust the issuer key
    add_trusted_key("trusted-univ", pub_pem, fp, "University Root", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/home",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Portal Access",
    )
    payload = create_signed_payload(record, priv)

    result = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert result["status"] == "VERIFIED"
    assert result["signature_valid"] is True
    assert result["issuer_trusted"] is True
    assert result["is_expired"] is False


def test_destination_tampering_invalidates_signature():
    """Scenario 2: Changing the destination URL after signing invalidates the signature."""
    priv, pub = generate_key_pair()
    pub_pem = export_public_key_pem(pub)
    fp = compute_public_key_fingerprint(pub)

    add_trusted_key("trusted-univ", pub_pem, fp, "University Root", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/home",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Portal Access",
    )
    payload = create_signed_payload(record, priv)

    # Malicious tampering: change destination to phishing site
    payload["record"]["destination_url"] = "https://phishing.attacker.com/login"

    result = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert result["status"] == "INVALID_SIGNATURE"
    assert result["signature_valid"] is False


def test_unknown_issuer_not_automatically_trusted():
    """Scenario 3: An unknown issuer is not automatically trusted even with a valid signature."""
    priv_bob, pub_bob = generate_key_pair()
    fp_bob = compute_public_key_fingerprint(pub_bob)
    pem_bob = export_public_key_pem(pub_bob)

    record = build_record_data(
        destination_url="https://unknown-service.com",
        issuer_id="untrusted-bob",
        issuer_fingerprint=fp_bob,
        purpose="Unknown Bob Service",
    )
    payload = create_signed_payload(record, priv_bob)

    # Bob's key is NOT added to trusted keys
    result = evaluate_linkproof_payload(payload, public_key_pem_override=pem_bob, offline_mode=True, db_path=":memory:")
    assert result["status"] == "UNKNOWN_ISSUER"
    assert result["signature_valid"] is True  # Cryptographic math checked with override
    assert result["issuer_trusted"] is False  # But NOT trusted!


def test_expired_record_identified():
    """Scenario 4: An expired record is identified and rejected."""
    priv, pub = generate_key_pair()
    pub_pem = export_public_key_pem(pub)
    fp = compute_public_key_fingerprint(pub)

    add_trusted_key("trusted-univ", pub_pem, fp, "University Root", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/event",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Old 2020 Event",
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    payload = create_signed_payload(record, priv)

    result = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert result["status"] == "EXPIRED_RECORD"
    assert result["is_expired"] is True


def test_malformed_payload_rejected_safely():
    """Scenario 5: Malformed payloads are handled gracefully without unhandled exceptions."""
    result1 = evaluate_linkproof_payload("string-not-dict", offline_mode=True, db_path=":memory:")
    assert result1["status"] == "MALFORMED_PAYLOAD"

    result2 = evaluate_linkproof_payload({"protocol": "linkproof"}, offline_mode=True, db_path=":memory:")
    assert result2["status"] == "MALFORMED_PAYLOAD"


def test_replay_duplicate_detection():
    """Scenario 13: Duplicate record detection flags previously verified record IDs."""
    priv, pub = generate_key_pair()
    pub_pem = export_public_key_pem(pub)
    fp = compute_public_key_fingerprint(pub)

    add_trusted_key("trusted-univ", pub_pem, fp, "University Root", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/single-use",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="One Time Event",
        record_id="fixed-uuid-12345678-abcd",
    )
    payload = create_signed_payload(record, priv)

    # First verification
    res1 = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res1["is_replay"] is False

    # Second verification with exact same record ID
    res2 = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res2["is_replay"] is True
    assert res2["replay_count"] >= 1
