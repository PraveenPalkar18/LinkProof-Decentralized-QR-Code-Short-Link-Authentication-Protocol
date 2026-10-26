"""Automated regression test suite enforcing correct verification outcomes.

Guarantees that:
1. Raw URLs and successful network audits are NEVER classified as VERIFIED.
2. Cryptographic authenticity requires valid ECDSA signature, trusted non-revoked issuer,
   active validity window, and compliant redirect policy.
3. Threat reputation defaults to NOT_CHECKED.
"""
from unittest.mock import MagicMock, patch
import pytest

from app import create_app
from config import TestConfig
from core.crypto import (
    compute_public_key_fingerprint,
    export_public_key_pem,
    generate_key_pair,
)
from core.record import build_record_data, create_signed_payload
from core.trust_store import evaluate_linkproof_payload
from models.database import (
    add_trusted_key,
    get_verification_by_id,
    get_verification_stats,
    init_db,
    record_verification,
)


@pytest.fixture
def test_app():
    """Create test Flask application."""
    app = create_app(test_config=TestConfig)
    return app


@pytest.fixture
def client(test_app):
    """Create Flask test client."""
    with test_app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def setup_db():
    """Ensure in-memory SQLite schema is freshly initialized and isolated."""
    from models.database import get_db_connection
    init_db(":memory:")
    with get_db_connection(":memory:") as conn:
        conn.execute("DELETE FROM verification_history")
        conn.execute("DELETE FROM trusted_keys")
        conn.commit()


# =========================================================================
# Scenario 1: Raw URL returning HTTP 200 with valid TLS is NOT marked VERIFIED
# =========================================================================

@patch("core.redirect_checker.inspect_url_redirect_chain")
def test_raw_url_http_200_valid_tls_not_marked_verified(mock_audit, client):
    """Raw URL with HTTP 200 and valid TLS must be AUDIT_COMPLETE_UNAUTHENTICATED, not VERIFIED."""
    mock_audit.return_value = {
        "initial_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "final_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "total_hops": 0,
        "hops": [
            {
                "hop": 0,
                "url": "https://testsafebrowsing.appspot.com/s/phishing.html",
                "status_code": 200,
                "is_https": True,
                "resolved_ip": "142.250.190.46",
                "server": "Google Frontend",
            }
        ],
        "redirect_policy": "same_host",
        "policy_satisfied": True,
        "policy_message": "Same Host satisfied",
        "loop_detected": False,
        "ssrf_blocked": False,
        "tls_summary": {
            "all_https": True,
            "any_tls_error": False,
            "certificates": [{"hostname": "testsafebrowsing.appspot.com", "valid": True}],
        },
        "success": True,
        "overall_status": "AUDIT_SUCCESS",
        "error": None,
    }

    # Verify via API endpoint
    resp = client.post("/api/verify", json={"url": "https://testsafebrowsing.appspot.com/s/phishing.html"})
    assert resp.status_code == 200
    data = resp.get_json()
    eval_res = data["evaluation"]

    # Must NOT be VERIFIED
    assert eval_res["status"] != "VERIFIED"
    assert eval_res["status"] == "AUDIT_COMPLETE_UNAUTHENTICATED"
    assert eval_res["is_raw_url"] is True
    assert eval_res["authenticity_status"] == "NOT_VERIFIED"
    assert eval_res["signature_valid"] is False
    assert eval_res["issuer_trusted"] is False
    assert eval_res["threat_reputation"] == "NOT_CHECKED"
    assert "not cryptographically authenticated" in eval_res["summary_message"]


# =========================================================================
# Scenario 2: Raw URL with satisfied redirect policy remains unauthenticated
# =========================================================================

@patch("core.redirect_checker.inspect_url_redirect_chain")
def test_raw_url_with_satisfied_redirect_policy_remains_unauthenticated(mock_audit, client):
    """Multi-hop raw URL that satisfies redirect policy remains unauthenticated."""
    mock_audit.return_value = {
        "initial_url": "https://example.com/short",
        "final_url": "https://example.com/dest",
        "total_hops": 1,
        "policy_satisfied": True,
        "success": True,
        "overall_status": "AUDIT_SUCCESS",
        "tls_summary": {"all_https": True, "any_tls_error": False, "certificates": []},
    }

    resp = client.post("/api/verify", json={"url": "https://example.com/short"})
    data = resp.get_json()["evaluation"]
    assert data["status"] == "AUDIT_COMPLETE_UNAUTHENTICATED"
    assert data["authenticity_status"] == "NOT_VERIFIED"


# =========================================================================
# Scenario 3: Raw URL with invalid TLS is not marked authenticated
# =========================================================================

@patch("core.redirect_checker.inspect_url_redirect_chain")
def test_raw_url_with_invalid_tls_not_marked_authenticated(mock_audit, client):
    """Raw URL with TLS validation errors must return TLS_VALIDATION_FAILED."""
    mock_audit.return_value = {
        "initial_url": "https://expired.badssl.com",
        "final_url": "https://expired.badssl.com",
        "total_hops": 0,
        "policy_satisfied": True,
        "success": False,
        "overall_status": "TLS_VALIDATION_FAILED",
        "tls_summary": {"all_https": True, "any_tls_error": True, "certificates": []},
        "error": "Certificate has expired",
    }

    resp = client.post("/api/verify", json={"url": "https://expired.badssl.com"})
    data = resp.get_json()["evaluation"]
    assert data["status"] == "TLS_VALIDATION_FAILED"
    assert data["authenticity_status"] == "NOT_VERIFIED"


# =========================================================================
# Scenario 4: Valid signature + trusted issuer succeeds (VERIFIED)
# =========================================================================

def test_valid_signature_and_trusted_issuer_succeeds():
    """Signed record with valid signature and trusted issuer receives VERIFIED."""
    priv, pub = generate_key_pair()
    pem = export_public_key_pem(pub)
    fp = compute_public_key_fingerprint(pub)

    add_trusted_key("trusted-univ", pem, fp, "Univ Key", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/login",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Admissions",
    )
    payload = create_signed_payload(record, priv)

    res = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res["status"] == "VERIFIED"
    assert res["authenticity_status"] == "AUTHENTICATED"
    assert res["signature_valid"] is True
    assert res["issuer_trusted"] is True


# =========================================================================
# Scenario 5: Tampered destination URL fails signature verification
# =========================================================================

def test_tampered_destination_url_fails_signature():
    """Modifying the destination URL after signing produces INVALID_SIGNATURE."""
    priv, pub = generate_key_pair()
    pem = export_public_key_pem(pub)
    fp = compute_public_key_fingerprint(pub)

    add_trusted_key("trusted-univ", pem, fp, "Univ Key", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/login",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Admissions",
    )
    payload = create_signed_payload(record, priv)
    # Attacker alters destination URL
    payload["record"]["destination_url"] = "https://phishing.evil.com/login"

    res = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res["status"] == "INVALID_SIGNATURE"
    assert res["authenticity_status"] == "INVALID"
    assert res["signature_valid"] is False


# =========================================================================
# Scenario 6: Invalid signature plus untrusted issuer cannot be authenticated
# =========================================================================

def test_invalid_signature_plus_untrusted_issuer_rejected():
    """Payload with tampered signature and unknown key cannot be VERIFIED."""
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)

    record = build_record_data(
        destination_url="https://random-site.com",
        issuer_id="unknown-actor",
        issuer_fingerprint=fp,
        purpose="Test",
    )
    payload = create_signed_payload(record, priv)
    payload["signature"] = "MEQCIBadSignaturePadding1234567890=="

    res = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res["status"] in ("INVALID_SIGNATURE", "UNKNOWN_ISSUER")
    assert res["authenticity_status"] in ("INVALID", "NOT_VERIFIED")
    assert res["status"] != "VERIFIED"


# =========================================================================
# Scenario 7: Unknown issuer cannot be authenticated even with valid math signature
# =========================================================================

def test_unknown_issuer_cannot_be_authenticated():
    """A valid signature signed by an untrusted key receives UNKNOWN_ISSUER."""
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    pem = export_public_key_pem(pub)

    record = build_record_data(
        destination_url="https://attacker.com",
        issuer_id="attacker-corp",
        issuer_fingerprint=fp,
        purpose="Phish",
    )
    payload = create_signed_payload(record, priv)

    # Provide override public key so crypto math is verified, but key is NOT in trust store
    res = evaluate_linkproof_payload(payload, public_key_pem_override=pem, offline_mode=True, db_path=":memory:")
    assert res["status"] == "UNKNOWN_ISSUER"
    assert res["authenticity_status"] == "NOT_VERIFIED"
    assert res["issuer_trusted"] is False


# =========================================================================
# Scenario 8: Revoked issuer key cannot be authenticated
# =========================================================================

def test_revoked_issuer_key_cannot_be_authenticated():
    """A public key explicitly marked un-trusted/revoked produces REVOKED_KEY."""
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    pem = export_public_key_pem(pub)

    # Register key with is_trusted=False (revoked)
    add_trusted_key("compromised-dept", pem, fp, "Compromised Key", is_trusted=False, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu",
        issuer_id="compromised-dept",
        issuer_fingerprint=fp,
        purpose="Access",
    )
    payload = create_signed_payload(record, priv)

    res = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res["status"] == "REVOKED_KEY"
    assert res["authenticity_status"] == "REVOKED"
    assert res["status"] != "VERIFIED"


# =========================================================================
# Scenario 9: Expired signed record cannot be authenticated
# =========================================================================

def test_expired_signed_record_cannot_be_authenticated():
    """Expired record receives EXPIRED_RECORD status."""
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    pem = export_public_key_pem(pub)

    add_trusted_key("trusted-univ", pem, fp, "Univ Key", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Past Event",
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    payload = create_signed_payload(record, priv)

    res = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert res["status"] == "EXPIRED_RECORD"
    assert res["authenticity_status"] == "EXPIRED"


# =========================================================================
# Scenario 10: Malformed payload and signature inputs are rejected safely
# =========================================================================

def test_malformed_payload_and_signature_rejected_safely():
    """Malformed payloads produce MALFORMED_PAYLOAD without crashing."""
    res1 = evaluate_linkproof_payload("string-not-dict", offline_mode=True, db_path=":memory:")
    assert res1["status"] == "MALFORMED_PAYLOAD"

    res2 = evaluate_linkproof_payload({"record": {}}, offline_mode=True, db_path=":memory:")
    assert res2["status"] == "MALFORMED_PAYLOAD"


# =========================================================================
# Scenario 11: Redirect-policy violation cannot produce authenticated success
# =========================================================================

@patch("core.trust_store.inspect_url_redirect_chain")
def test_redirect_policy_violation_cannot_produce_authenticated_success(mock_audit):
    """Valid signature whose destination redirects to unauthorized domain produces DESTINATION_MISMATCH."""
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    pem = export_public_key_pem(pub)

    add_trusted_key("trusted-univ", pem, fp, "Univ Key", is_trusted=True, db_path=":memory:")

    record = build_record_data(
        destination_url="https://portal.university.edu/login",
        issuer_id="trusted-univ",
        issuer_fingerprint=fp,
        purpose="Portal",
        redirect_policy="same_host",
    )
    payload = create_signed_payload(record, priv)

    # Mock audit showing destination redirected to unauthorized domain
    mock_audit.return_value = {
        "final_url": "https://malicious-phishing.com/login",
        "policy_satisfied": False,
        "policy_message": "Same Host Violation",
        "loop_detected": False,
        "ssrf_blocked": False,
        "tls_summary": {"all_https": True, "any_tls_error": False, "certificates": []},
        "success": False,
        "overall_status": "DESTINATION_MISMATCH",
    }

    res = evaluate_linkproof_payload(payload, offline_mode=False, db_path=":memory:")
    assert res["status"] == "DESTINATION_MISMATCH"
    assert res["status"] != "VERIFIED"


# =========================================================================
# Scenario 12: SSRF-blocked requests cannot be reported as successful audits
# =========================================================================

def test_ssrf_blocked_requests_not_reported_as_success():
    """Requests targeting private or loopback ranges receive SSRF_BLOCKED."""
    from core.redirect_checker import inspect_url_redirect_chain
    report = inspect_url_redirect_chain("http://127.0.0.1:8080/admin")
    assert report["ssrf_blocked"] is True
    assert report["overall_status"] == "SSRF_BLOCKED"
    assert report["success"] is False


# =========================================================================
# Scenario 13: Missing threat intelligence is represented as NOT_CHECKED
# =========================================================================

def test_missing_threat_intelligence_is_not_checked(client):
    """Threat reputation is explicitly NOT_CHECKED, never SAFE or CLEAN."""
    # Test on raw URL
    resp = client.post("/api/verify", json={"url": "https://example.com"})
    eval_raw = resp.get_json()["evaluation"]
    assert eval_raw["threat_reputation"] == "NOT_CHECKED"

    # Test on signed record
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    rec = build_record_data("https://example.com", "issuer", fp, "test")
    payload = create_signed_payload(rec, priv)
    eval_signed = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert eval_signed["threat_reputation"] == "NOT_CHECKED"


# =========================================================================
# Scenario 14: HTML report, JSON response, and dashboard metrics consistency
# =========================================================================

def test_dashboard_metrics_do_not_count_unauthenticated_raw_audits():
    """Dashboard verified metric counts ONLY valid authenticated records, not raw audits."""
    # Record 1: Genuinely verified signed record
    record_verification(
        destination_url="https://portal.university.edu",
        status="VERIFIED",
        signature_valid=True,
        issuer_trusted=True,
        db_path=":memory:",
    )

    # Record 2: Raw URL audit complete (unauthenticated)
    record_verification(
        destination_url="https://testsafebrowsing.appspot.com/s/phishing.html",
        status="AUDIT_COMPLETE_UNAUTHENTICATED",
        issuer_id="UNTRUSTED_RAW_URL",
        signature_valid=False,
        issuer_trusted=False,
        db_path=":memory:",
    )

    stats = get_verification_stats(db_path=":memory:")
    assert stats["verified"] == 1  # ONLY the authentic record is counted
    assert stats["unauthenticated_audits"] == 1
    assert stats["total"] == 2


# =========================================================================
# Scenario 15: Exceptions or missing fields cannot silently default to VERIFIED
# =========================================================================

def test_exceptions_or_missing_fields_never_default_to_verified():
    """Invalid dictionaries, missing keys, or errors never evaluate to VERIFIED."""
    test_cases = [
        {},
        {"protocol": "unknown"},
        {"protocol": "linkproof", "version": "99.9"},
        {"protocol": "linkproof", "version": "1.0", "record": None},
        {"protocol": "linkproof", "version": "1.0", "record": {}, "signature": ""},
    ]
    for case in test_cases:
        res = evaluate_linkproof_payload(case, offline_mode=True, db_path=":memory:")
        assert res["status"] != "VERIFIED"
        assert res["status"] == "MALFORMED_PAYLOAD"
