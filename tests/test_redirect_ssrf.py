"""Test suite for SSRF filtering, multi-hop redirect verification, and policy enforcement."""
from unittest.mock import MagicMock, patch
import pytest

from core.redirect_checker import (
    check_redirect_policy,
    inspect_url_redirect_chain,
    is_ip_allowed,
    validate_destination_safety,
)


def test_ssrf_ip_filter_blocks_unsafe_addresses():
    """Verify that loopback, RFC1918 private, link-local, and multicast IPs are blocked."""
    # Loopback
    ok, reason = is_ip_allowed("127.0.0.1")
    assert ok is False
    assert "Loopback" in reason

    ok, reason = is_ip_allowed("127.0.1.50")
    assert ok is False

    ok, reason = is_ip_allowed("::1")
    assert ok is False

    # RFC 1918 Private
    ok, reason = is_ip_allowed("10.0.0.1")
    assert ok is False
    assert "Private" in reason

    ok, reason = is_ip_allowed("172.16.0.1")
    assert ok is False

    ok, reason = is_ip_allowed("192.168.1.100")
    assert ok is False

    # Link-local (e.g. AWS metadata 169.254.169.254)
    ok, reason = is_ip_allowed("169.254.169.254")
    assert ok is False
    assert "Link-local" in reason

    # Unspecified 0.0.0.0
    ok, reason = is_ip_allowed("0.0.0.0")
    assert ok is False

    # Public IPs should be allowed
    ok, _ = is_ip_allowed("8.8.8.8")
    assert ok is True

    ok, _ = is_ip_allowed("93.184.216.34")
    assert ok is True


def test_redirect_policy_enforcement():
    """Verify redirect policy checking logic."""
    # 1. strict_exact
    ok, _ = check_redirect_policy("https://example.com/page", "https://example.com/page", "strict_exact", True)
    assert ok is True

    ok, msg = check_redirect_policy("https://example.com/page", "https://example.com/another", "strict_exact", True)
    assert ok is False
    assert "Strict Exact Violation" in msg

    # 2. same_host
    ok, _ = check_redirect_policy("https://example.com/page", "https://example.com/dashboard", "same_host", True)
    assert ok is True

    ok, msg = check_redirect_policy("https://example.com/page", "https://malicious.com/phish", "same_host", True)
    assert ok is False
    assert "Same Host Violation" in msg

    # 3. same_registered_domain
    ok, _ = check_redirect_policy("https://sub1.example.com", "https://sub2.example.com", "same_registered_domain", True)
    assert ok is True

    ok, msg = check_redirect_policy("https://example.com", "https://attacker.org", "same_registered_domain", True)
    assert ok is False

    # 4. allow_any_tls
    ok, _ = check_redirect_policy("https://start.com", "https://anywhere.org", "allow_any_tls", True)
    assert ok is True

    ok, msg = check_redirect_policy("https://start.com", "http://insecure.org", "allow_any_tls", False)
    assert ok is False
    assert "HTTPS Audit Violation" in msg


@patch("core.redirect_checker.validate_destination_safety")
@patch("requests.Session.get")
def test_relative_redirect_resolution(mock_get, mock_safety):
    """Verify that relative redirect Location headers are resolved safely."""
    mock_safety.return_value = (True, "Destination safe", "93.184.216.34")

    # Hop 0 redirects to relative path "/login"
    resp0 = MagicMock()
    resp0.status_code = 302
    resp0.headers = {"Location": "/login", "Server": "nginx"}
    resp0.raw.read.return_value = b""

    # Hop 1 returns 200 OK
    resp1 = MagicMock()
    resp1.status_code = 200
    resp1.headers = {"Server": "nginx"}
    resp1.raw.read.return_value = b"OK"

    mock_get.side_effect = [resp0, resp1]

    report = inspect_url_redirect_chain("https://example.com/start", redirect_policy="same_host")
    assert report["final_url"] == "https://example.com/login"
    assert report["total_hops"] == 1
    assert report["policy_satisfied"] is True


@patch("core.redirect_checker.validate_destination_safety")
@patch("requests.Session.get")
def test_redirect_loop_detection(mock_get, mock_safety):
    """Verify that a circular redirect loop is detected and aborted."""
    mock_safety.return_value = (True, "Destination safe", "93.184.216.34")

    # Hop 0 -> /loop
    resp0 = MagicMock()
    resp0.status_code = 301
    resp0.headers = {"Location": "https://example.com/loop"}
    resp0.raw.read.return_value = b""

    # Hop 1 -> /start (circular back to initial)
    resp1 = MagicMock()
    resp1.status_code = 301
    resp1.headers = {"Location": "https://example.com/start"}
    resp1.raw.read.return_value = b""

    mock_get.side_effect = [resp0, resp1]

    report = inspect_url_redirect_chain("https://example.com/start", redirect_policy="same_host")
    assert report["loop_detected"] is True
    assert report["overall_status"] == "REDIRECT_LOOP"


def test_ssrf_blocks_redirect_to_private_address():
    """Verify that attempting to redirect to a loopback or private IP is blocked."""
    report = inspect_url_redirect_chain("http://127.0.0.1:8080/internal-admin")
    assert report["ssrf_blocked"] is True
    assert report["overall_status"] == "SSRF_BLOCKED"


@patch("core.redirect_checker.validate_destination_safety")
@patch("requests.Session.get")
def test_redirect_count_distinguishes_initial_from_redirects(mock_get, mock_safety):
    """Ensure report accurately distinguishes an initial direct response from actual redirects."""
    mock_safety.return_value = (True, "Destination safe", "93.184.216.34")

    # Case 1: Direct response (No redirects)
    resp_direct = MagicMock()
    resp_direct.status_code = 200
    resp_direct.headers = {"Server": "nginx"}
    resp_direct.raw.read.return_value = b"Direct Response Content"
    mock_get.side_effect = [resp_direct]

    report_direct = inspect_url_redirect_chain("https://example.com/direct")
    assert report_direct["redirect_count"] == 0
    assert report_direct["total_requests"] == 1
    assert report_direct["is_redirected"] is False

    # Case 2: One redirect followed by 200 OK
    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {"Location": "https://example.com/target", "Server": "nginx"}
    resp_redirect.raw.read.return_value = b""

    resp_target = MagicMock()
    resp_target.status_code = 200
    resp_target.headers = {"Server": "nginx"}
    resp_target.raw.read.return_value = b"Target Content"
    mock_get.side_effect = [resp_redirect, resp_target]

    report_redirected = inspect_url_redirect_chain("https://example.com/source", redirect_policy="same_host")
    assert report_redirected["redirect_count"] == 1
    assert report_redirected["total_requests"] == 2
    assert report_redirected["is_redirected"] is True

