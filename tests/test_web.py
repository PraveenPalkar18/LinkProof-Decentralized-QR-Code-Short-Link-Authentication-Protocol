import json
from unittest.mock import patch
import pytest
from app import create_app
from config import TestConfig
from core.crypto import compute_public_key_fingerprint, generate_key_pair, export_private_key_pem


@pytest.fixture
def client():
    """Create Flask test client with test configuration."""
    app = create_app(test_config=TestConfig)
    with app.test_client() as client:
        yield client


def test_public_pages_render_successfully(client):
    """Verify that all core dashboard, verify, generate, keys, and about routes respond 200."""
    routes = ["/", "/generate", "/verify", "/keys", "/about"]
    for route in routes:
        resp = client.get(route)
        assert resp.status_code == 200
        assert b"LinkProof" in resp.data


def test_security_headers_present(client):
    """Verify security headers are applied to HTTP responses."""
    resp = client.get("/")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in resp.headers


def test_csrf_protection_rejects_unauthenticated_post(client):
    """Verify state-changing POST requests without CSRF token are blocked with 403."""
    resp = client.post("/generate/key", data={"issuer_id": "test", "passphrase": "secretpassword"})
    assert resp.status_code == 403


def test_private_keys_not_exposed_in_responses(client):
    """Scenario 14: Private keys are not exposed through web routes or logs."""
    # Check that keys listing never discloses private keys
    resp = client.get("/keys")
    assert resp.status_code == 200
    assert b"BEGIN PRIVATE KEY" not in resp.data
    assert b"BEGIN EC PRIVATE KEY" not in resp.data

    # Check dashboard
    dash_resp = client.get("/")
    assert b"BEGIN PRIVATE KEY" not in dash_resp.data


def test_api_generate_and_verify(client):
    """Verify programmatic JSON API endpoints."""
    priv, pub = generate_key_pair()
    priv_pem = export_private_key_pem(priv)

    gen_payload = {
        "destination_url": "https://university.edu/student-hub",
        "issuer_id": "api-issuer",
        "private_key_pem": priv_pem,
        "purpose": "API Test",
    }
    resp = client.post("/api/generate", json=gen_payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    signed_payload = data["payload"]

    # Verify via API
    ver_resp = client.post("/api/verify", json={"payload": signed_payload, "offline": True})
    assert ver_resp.status_code == 200
    ver_data = ver_resp.get_json()
    # Unknown issuer since not in trust store
    assert ver_data["evaluation"]["status"] == "UNKNOWN_ISSUER"


@patch("core.redirect_checker.inspect_url_redirect_chain")
def test_web_raw_url_audit_html_renders_unauthenticated(mock_audit, client):
    """Verify that inspecting a raw URL via the web interface renders unauthenticated status and warning."""
    mock_audit.return_value = {
        "initial_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "final_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "total_hops": 0,
        "hops": [],
        "redirect_policy": "same_host",
        "policy_satisfied": True,
        "policy_message": "Same Host satisfied",
        "loop_detected": False,
        "ssrf_blocked": False,
        "tls_summary": {"all_https": True, "any_tls_error": False, "certificates": []},
        "success": True,
        "overall_status": "AUDIT_SUCCESS",
        "error": None,
    }

    # Fetch verify page to populate session CSRF token
    get_resp = client.get("/verify")
    assert get_resp.status_code == 200

    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    post_resp = client.post(
        "/verify",
        data={
            "csrf_token": csrf_tok,
            "input_mode": "url",
            "raw_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        },
        follow_redirects=True,
    )
    assert post_resp.status_code == 200
    html_content = post_resp.data.decode("utf-8")

    # MUST show AUDIT COMPLETE (UNAUTHENTICATED)
    assert "AUDIT COMPLETE (UNAUTHENTICATED)" in html_content
    # MUST NOT show green overall ✓ VERIFIED badge
    assert '<span class="badge badge-verified" style="font-size: 1rem; padding: 0.4rem 1rem;">✓ VERIFIED</span>' not in html_content
    # MUST display the explicit security notice
    assert "This URL was not cryptographically authenticated." in html_content
    # Threat reputation must be NOT_CHECKED
    assert "NOT_CHECKED" in html_content
