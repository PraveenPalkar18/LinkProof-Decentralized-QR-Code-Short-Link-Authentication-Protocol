"""Comprehensive test suite for Google Safe Browsing Threat Reputation Engine.

Covers:
- Phishing / Social Engineering detection
- Malware detection
- No known threats (clean response)
- Missing API key (NOT_CHECKED)
- Offline audit mode (NOT_CHECKED)
- Network timeouts (CHECK_UNAVAILABLE)
- HTTP 429 Quota exhaustion (CHECK_UNAVAILABLE)
- HTTP 500 / 503 Provider error (CHECK_UNAVAILABLE)
- Malformed JSON responses (CHECK_UNAVAILABLE)
- URL normalization without tampering signed records
- Separation of concerns: reputation never overrides signature or trust failures
"""
from unittest.mock import MagicMock, patch
import pytest
import requests

from app import create_app
from config import TestConfig
from core.crypto import (
    compute_public_key_fingerprint,
    export_public_key_pem,
    generate_key_pair,
)
from core.record import build_record_data, create_signed_payload
from core.threat_reputation import (
    check_urls_reputation,
    normalize_url_for_lookup,
    query_google_safe_browsing,
)
from core.trust_store import evaluate_linkproof_payload
from models.database import add_trusted_key, init_db


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
# 1. URL Normalization Tests
# =========================================================================

def test_url_normalization_handles_various_formats():
    """Verify URL normalization applies RFC 3986 rules without mutating the original."""
    # Strips port 80 for HTTP
    assert normalize_url_for_lookup("http://EXAMPLE.COM:80/path") == "http://example.com/path"
    # Strips port 443 for HTTPS
    assert normalize_url_for_lookup("https://EXAMPLE.COM:443/login") == "https://example.com/login"
    # Preserves non-default port
    assert normalize_url_for_lookup("https://example.com:8443/api") == "https://example.com:8443/api"
    # Adds leading slash if path empty
    assert normalize_url_for_lookup("https://example.com") == "https://example.com/"
    # Strips fragments
    assert normalize_url_for_lookup("https://example.com/page#section") == "https://example.com/page"
    # Rejects non-HTTP schemes
    assert normalize_url_for_lookup("javascript:alert(1)") is None
    assert normalize_url_for_lookup("file:///etc/passwd") is None


# =========================================================================
# 2. Engine State Tests (Unit Level)
# =========================================================================

def test_missing_api_key_returns_not_checked():
    """Ensure that missing GOOGLE_SAFE_BROWSING_API_KEY yields NOT_CHECKED state."""
    with patch("core.threat_reputation.get_api_key", return_value=None):
        res = check_urls_reputation("https://example.com", api_key=None)
        assert res["status"] == "NOT_CHECKED"
        assert "not configured" in res["message"]


def test_offline_mode_returns_not_checked():
    """Ensure offline verification skips threat reputation lookups."""
    res = check_urls_reputation("https://example.com", api_key="dummy-key", offline_mode=True)
    assert res["status"] == "NOT_CHECKED"
    assert "Offline audit mode active" in res["message"]


@patch("requests.post")
def test_no_known_threat_reported(mock_post):
    """Ensure empty matches response yields NO_KNOWN_THREAT."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}  # Empty dict per Google Safe Browsing specification
    mock_post.return_value = mock_resp

    res = query_google_safe_browsing(["https://example.com/clean"], api_key="dummy-key")
    assert res["status"] == "NO_KNOWN_THREAT"
    assert res["threat_type"] is None
    assert "No known threats reported" in res["message"]


@patch("requests.post")
def test_phishing_social_engineering_detected(mock_post):
    """Ensure SOCIAL_ENGINEERING response yields THREAT_DETECTED."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "https://testsafebrowsing.appspot.com/s/phishing.html"},
                "threatEntryType": "URL",
            }
        ]
    }
    mock_post.return_value = mock_resp

    res = query_google_safe_browsing(["https://testsafebrowsing.appspot.com/s/phishing.html"], api_key="dummy-key")
    assert res["status"] == "THREAT_DETECTED"
    assert res["threat_type"] == "SOCIAL_ENGINEERING"
    assert "Phishing / Social Engineering" in res["threat_category"]
    assert "testsafebrowsing.appspot.com" in res["threat_url"]


@patch("requests.post")
def test_malware_detected(mock_post):
    """Ensure MALWARE response yields THREAT_DETECTED."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "https://testsafebrowsing.appspot.com/s/malware.html"},
                "threatEntryType": "URL",
            }
        ]
    }
    mock_post.return_value = mock_resp

    res = query_google_safe_browsing(["https://testsafebrowsing.appspot.com/s/malware.html"], api_key="dummy-key")
    assert res["status"] == "THREAT_DETECTED"
    assert res["threat_type"] == "MALWARE"
    assert "Malware" in res["threat_category"]


@patch("requests.post")
def test_api_timeout_returns_check_unavailable(mock_post):
    """Ensure network timeouts return CHECK_UNAVAILABLE without failing overall flow."""
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

    res = query_google_safe_browsing(["https://example.com"], api_key="dummy-key", timeout=2.0)
    assert res["status"] == "CHECK_UNAVAILABLE"
    assert "timed out" in res["message"]


@patch("requests.post")
def test_quota_limit_429_returns_check_unavailable(mock_post):
    """Ensure HTTP 429 quota exhaustion yields CHECK_UNAVAILABLE."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_post.return_value = mock_resp

    res = query_google_safe_browsing(["https://example.com"], api_key="dummy-key")
    assert res["status"] == "CHECK_UNAVAILABLE"
    assert "quota exceeded" in res["message"]


@patch("requests.post")
def test_http_500_error_returns_check_unavailable(mock_post):
    """Ensure HTTP 500 server error yields CHECK_UNAVAILABLE."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_post.return_value = mock_resp

    res = query_google_safe_browsing(["https://example.com"], api_key="dummy-key")
    assert res["status"] == "CHECK_UNAVAILABLE"
    assert "HTTP 500" in res["message"]


@patch("requests.post")
def test_malformed_json_response_returns_check_unavailable(mock_post):
    """Ensure non-JSON response yields CHECK_UNAVAILABLE safely."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")
    mock_post.return_value = mock_resp

    res = query_google_safe_browsing(["https://example.com"], api_key="dummy-key")
    assert res["status"] == "CHECK_UNAVAILABLE"
    assert "Malformed response" in res["message"]


# =========================================================================
# 3. Separation of Concerns & Security Integration Tests
# =========================================================================

@patch("core.threat_reputation.check_urls_reputation")
def test_threat_detected_does_not_override_signature_failure(mock_rep):
    """A tampered payload must fail with INVALID_SIGNATURE even if malware is detected."""
    mock_rep.return_value = {
        "status": "THREAT_DETECTED",
        "threat_type": "MALWARE",
        "threat_category": "Malware / Exploit",
        "threat_url": "https://example.com/tampered",
        "message": "Malware identified",
    }

    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    add_trusted_key(issuer_id="cns.edu", public_key_pem=export_public_key_pem(pub), fingerprint=fp, is_trusted=True)

    record_data = build_record_data(
        destination_url="https://example.com/original",
        issuer_id="cns.edu",
        issuer_fingerprint=fp,
        purpose="Security Testing",
    )
    payload = create_signed_payload(record_data, priv)

    # Tamper destination URL
    payload["record"]["destination_url"] = "https://example.com/tampered"

    eval_res = evaluate_linkproof_payload(payload, offline_mode=True)
    # Must remain INVALID_SIGNATURE
    assert eval_res["status"] == "INVALID_SIGNATURE"
    assert eval_res["authenticity_status"] == "INVALID"
    assert eval_res["signature_valid"] is False


@patch("core.trust_store.check_urls_reputation")
def test_threat_detected_does_not_make_untrusted_issuer_trusted(mock_rep):
    """An unknown issuer key must remain UNKNOWN_ISSUER even when Safe Browsing reports NO_KNOWN_THREAT."""
    mock_rep.return_value = {
        "status": "NO_KNOWN_THREAT",
        "threat_type": None,
        "message": "No known threats",
    }

    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    # Do NOT register public key in trust store

    record_data = build_record_data(
        destination_url="https://example.com/portal",
        issuer_id="unknown.org",
        issuer_fingerprint=fp,
        purpose="Testing Unknown Issuer",
    )
    payload = create_signed_payload(record_data, priv)

    eval_res = evaluate_linkproof_payload(payload, offline_mode=True, db_path=":memory:")
    assert eval_res["status"] == "UNKNOWN_ISSUER"
    assert eval_res["authenticity_status"] == "NOT_VERIFIED"
    assert eval_res["issuer_trusted"] is False


@patch("core.trust_store.check_urls_reputation")
@patch("core.redirect_checker.inspect_url_redirect_chain")
def test_authentic_record_with_threat_flagged_as_threat_detected(mock_audit, mock_rep):
    """When a legitimate trusted record points to a flagged threat, overall status becomes THREAT_DETECTED."""
    mock_audit.return_value = {
        "success": True,
        "overall_status": "AUDIT_SUCCESS",
        "final_url": "https://example.com/phish",
        "policy_satisfied": True,
        "total_hops": 0,
        "hops": [],
        "tls_summary": {"all_https": True, "any_tls_error": False},
    }
    mock_rep.return_value = {
        "status": "THREAT_DETECTED",
        "threat_type": "SOCIAL_ENGINEERING",
        "threat_category": "Phishing / Social Engineering",
        "threat_url": "https://example.com/phish",
        "message": "Phishing threat detected by Google Safe Browsing",
    }

    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)
    add_trusted_key(issuer_id="trusted.edu", public_key_pem=export_public_key_pem(pub), fingerprint=fp, is_trusted=True)

    record_data = build_record_data(
        destination_url="https://example.com/phish",
        issuer_id="trusted.edu",
        issuer_fingerprint=fp,
        purpose="Legitimate Campus Notice",
    )
    payload = create_signed_payload(record_data, priv)

    eval_res = evaluate_linkproof_payload(payload, offline_mode=False)
    # Signature is mathematically authentic from trusted issuer
    assert eval_res["signature_valid"] is True
    assert eval_res["issuer_trusted"] is True
    assert eval_res["authenticity_status"] == "AUTHENTICATED"
    # But overall status must alert the user that a threat was detected!
    assert eval_res["status"] == "THREAT_DETECTED"
    assert "CRITICAL SECURITY ALERT" in eval_res["summary_message"]
    assert eval_res["threat_reputation"] == "THREAT_DETECTED"


@patch("routes.api.check_urls_reputation")
@patch("core.redirect_checker.inspect_url_redirect_chain")
def test_raw_url_audit_with_phishing_detected_returns_threat_detected(mock_audit, mock_rep, client):
    """Raw URL audit with Google Safe Browsing threat detected returns THREAT_DETECTED."""
    mock_audit.return_value = {
        "success": True,
        "overall_status": "AUDIT_SUCCESS",
        "final_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "policy_satisfied": True,
        "total_hops": 0,
        "hops": [],
        "tls_summary": {"all_https": True, "any_tls_error": False},
    }
    mock_rep.return_value = {
        "status": "THREAT_DETECTED",
        "threat_type": "SOCIAL_ENGINEERING",
        "threat_category": "Phishing / Social Engineering",
        "threat_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "message": "Google Safe Browsing identified Phishing on destination.",
    }

    resp = client.post("/api/verify", json={"url": "https://testsafebrowsing.appspot.com/s/phishing.html"})
    data = resp.get_json()
    assert data["success"] is True
    eval_res = data["evaluation"]
    assert eval_res["status"] == "THREAT_DETECTED"
    assert eval_res["authenticity_status"] == "NOT_VERIFIED"
    assert eval_res["threat_reputation"] == "THREAT_DETECTED"
    assert "CRITICAL SECURITY ALERT" in eval_res["summary_message"]


@patch("core.threat_reputation.query_google_safe_browsing")
def test_deduplication_of_urls_in_reputation_query(mock_query):
    """Ensure duplicate URLs across redirect hops are deduplicated before provider call."""
    mock_query.return_value = {"status": "NO_KNOWN_THREAT", "message": "Clean"}

    urls = [
        "https://example.com/start",
        "https://example.com/start",  # Duplicate
        "https://example.com/target",
        "https://example.com/target/",  # Resolves to same normalized
    ]
    check_urls_reputation(urls, api_key="test-key")

    mock_query.assert_called_once()
    called_urls = mock_query.call_args[0][0]
    # Should contain exactly 2 unique normalized URLs
    assert len(called_urls) == 2
    assert "https://example.com/start" in called_urls
    assert "https://example.com/target" in called_urls
