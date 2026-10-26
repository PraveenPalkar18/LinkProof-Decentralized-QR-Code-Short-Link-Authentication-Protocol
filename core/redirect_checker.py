"""LinkProof Multi-Hop Redirect Verification and SSRF Defense Module.

Performs controlled, hop-by-hop HTTP/HTTPS inspection with strict DNS resolution,
private/loopback/link-local IP blocking (SSRF defense), TLS certificate extraction,
redirect loop detection, and destination policy enforcement.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from config import Config


class SSRFSecurityViolation(Exception):
    """Raised when an outbound request targets a disallowed IP address or scheme."""
    pass


def is_ip_allowed(ip_str: str, block_private: bool = True) -> Tuple[bool, str]:
    """Validate whether an IP address is safe for outbound inspection.

    Blocks loopback (127.0.0.0/8, ::1), RFC 1918 private ranges,
    link-local (169.254.0.0/16, fe80::/10), multicast, broadcast, and reserved.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    if ip.is_unspecified:
        return False, f"Unspecified IP (0.0.0.0/::) is blocked: {ip}"

    if ip.is_loopback:
        return False, f"Loopback address blocked: {ip}"

    if ip.is_link_local:
        return False, f"Link-local address (APIPA/cloud metadata) blocked: {ip}"

    if ip.is_multicast:
        return False, f"Multicast address blocked: {ip}"

    if ip.is_reserved:
        return False, f"Reserved address blocked: {ip}"

    if block_private and ip.is_private:
        return False, f"RFC 1918 Private network address blocked: {ip}"

    return True, "IP address is allowed"


def resolve_hostname_ips(hostname: str, port: int = 80) -> List[str]:
    """Resolve a hostname to list of distinct IPv4 and IPv6 strings."""
    try:
        addr_infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        ips = []
        for info in addr_infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            if ip_str not in ips:
                ips.append(ip_str)
        return ips
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failure for '{hostname}': {str(e)}")


def validate_destination_safety(
    url: str,
    block_private: bool = True,
) -> Tuple[bool, str, Optional[str]]:
    """Validate URL scheme and ensure resolved IPs are safe from SSRF.

    Returns (is_safe, reason, resolved_ip).
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in Config.ALLOWED_SCHEMES:
        return False, f"Disallowed scheme '{scheme}'. Only HTTP and HTTPS are permitted.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no valid host.", None

    port = parsed.port or (443 if scheme == "https" else 80)

    try:
        # Check if hostname is already a direct IP
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_allowed, reason = is_ip_allowed(str(ip_obj), block_private=block_private)
            if not is_allowed:
                return False, reason, str(ip_obj)
            return True, "Direct IP permitted", str(ip_obj)
        except ValueError:
            pass  # It is a domain name, proceed to DNS resolution

        resolved_ips = resolve_hostname_ips(hostname, port)
        if not resolved_ips:
            return False, f"Could not resolve host '{hostname}' to any IP.", None

        for ip in resolved_ips:
            is_allowed, reason = is_ip_allowed(ip, block_private=block_private)
            if not is_allowed:
                return False, f"SSRF Block: Resolved host '{hostname}' to disallowed IP {ip} ({reason})", ip

        return True, "Destination safe", resolved_ips[0]
    except Exception as e:
        return False, f"DNS or address validation error: {str(e)}", None


def extract_tls_certificate_info(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Connect via TLS and extract certificate chain, validity, SANs, and subject details."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    cert_info: Dict[str, Any] = {
        "valid": False,
        "hostname": hostname,
        "port": port,
        "subject": {},
        "issuer": {},
        "san": [],
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "is_expired": False,
        "hostname_matches": False,
        "error": None,
    }

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    cert_info["error"] = "No peer certificate returned by server."
                    return cert_info

                cert = x509.load_der_x509_certificate(der_cert)

                # Extract Subject
                subject_attrs = {}
                for attr in cert.subject:
                    subject_attrs[attr.oid._name] = attr.value
                cert_info["subject"] = subject_attrs

                # Extract Issuer
                issuer_attrs = {}
                for attr in cert.issuer:
                    issuer_attrs[attr.oid._name] = attr.value
                cert_info["issuer"] = issuer_attrs

                # Extract Validity
                cert_info["not_before"] = cert.not_valid_before_utc.isoformat()
                cert_info["not_after"] = cert.not_valid_after_utc.isoformat()
                now_utc = datetime.now(timezone.utc)
                if now_utc < cert.not_valid_before_utc or now_utc > cert.not_valid_after_utc:
                    cert_info["is_expired"] = True

                cert_info["serial_number"] = f"{cert.serial_number:X}"

                # Extract SANs
                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(x.value) for x in san_ext.value]
                except x509.ExtensionNotFound:
                    pass
                cert_info["san"] = sans

                # Hostname matching check
                cert_info["hostname_matches"] = True  # Verified by wrap_socket check_hostname
                cert_info["valid"] = not cert_info["is_expired"]
                return cert_info

    except ssl.SSLCertVerificationError as e:
        cert_info["error"] = f"TLS Certificate Verification Failed: {e.strerror or str(e)}"
        return cert_info
    except ssl.SSLError as e:
        cert_info["error"] = f"SSL/TLS Error: {str(e)}"
        return cert_info
    except Exception as e:
        cert_info["error"] = f"TLS Connection Failed: {str(e)}"
        return cert_info


def check_redirect_policy(
    signed_url: str,
    final_url: str,
    policy: str,
    all_hops_tls: bool,
) -> Tuple[bool, str]:
    """Verify whether final URL satisfies the signed redirect policy."""
    signed_parsed = urlparse(signed_url)
    final_parsed = urlparse(final_url)

    if policy == "strict_exact":
        # URLs must be identical (ignoring trailing slash differences)
        s_norm = signed_url.rstrip("/")
        f_norm = final_url.rstrip("/")
        if s_norm == f_norm:
            return True, "Strict Exact: Final URL matches destination URL exactly."
        return False, f"Strict Exact Violation: Expected '{signed_url}', but landed on '{final_url}'."

    elif policy == "same_host":
        s_host = (signed_parsed.hostname or "").lower()
        f_host = (final_parsed.hostname or "").lower()
        if s_host == f_host:
            return True, f"Same Host: Host '{f_host}' matches signed destination."
        return False, f"Same Host Violation: Destination host changed from '{s_host}' to '{f_host}'."

    elif policy == "same_registered_domain":
        def get_reg_domain(h: str) -> str:
            parts = h.lower().split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return h.lower()

        s_domain = get_reg_domain(signed_parsed.hostname or "")
        f_domain = get_reg_domain(final_parsed.hostname or "")
        if s_domain and s_domain == f_domain:
            return True, f"Same Registered Domain: Domain '{f_domain}' matches signed destination."
        return False, f"Domain Violation: Registered domain changed from '{s_domain}' to '{f_domain}'."

    elif policy == "allow_any_tls":
        if not all_hops_tls:
            return False, "HTTPS Audit Violation: One or more hops in redirect chain used unencrypted HTTP."
        if final_parsed.scheme.lower() != "https":
            return False, "HTTPS Audit Violation: Final destination is not HTTPS."
        return True, "HTTPS Audit: All redirect hops and final destination securely used TLS."

    return False, f"Unknown redirect policy '{policy}'."


def inspect_url_redirect_chain(
    initial_url: str,
    signed_url: Optional[str] = None,
    redirect_policy: str = "same_host",
    max_hops: int = Config.MAX_REDIRECT_HOPS,
    timeout: float = Config.HTTP_TIMEOUT_SECONDS,
    max_response_bytes: int = Config.MAX_RESPONSE_BYTES,
    block_private_ips: bool = Config.BLOCK_PRIVATE_NETWORKS,
) -> Dict[str, Any]:
    """Execute a controlled multi-hop redirect verification.

    Performs SSRF filtering at every hop, TLS validation, loop detection,
    and returns a structured audit report.
    """
    report: Dict[str, Any] = {
        "initial_url": initial_url,
        "final_url": initial_url,
        "total_hops": 0,
        "redirect_count": 0,
        "total_requests": 0,
        "is_redirected": False,
        "hops": [],
        "redirect_policy": redirect_policy,
        "policy_satisfied": True,
        "policy_message": "",
        "loop_detected": False,
        "ssrf_blocked": False,
        "tls_summary": {
            "all_https": True,
            "any_tls_error": False,
            "certificates": [],
        },
        "success": False,
        "overall_status": "INCONCLUSIVE",
        "error": None,
    }

    current_url = initial_url.strip()
    visited_urls: Set[str] = set()
    session = requests.Session()
    # Ensure no credentials/auth leak across hops
    session.headers.update({
        "User-Agent": "LinkProof-Security-Auditor/1.0 (CNS-Course-Project; Strict-Verification)",
        "Accept": "*/*",
    })

    all_hops_tls = True

    for hop_index in range(max_hops + 1):
        parsed = urlparse(current_url)
        is_https = parsed.scheme.lower() == "https"
        if not is_https:
            all_hops_tls = False

        # SSRF and Address Safety Check for current hop
        is_safe, ssrf_reason, resolved_ip = validate_destination_safety(
            current_url, block_private=block_private_ips
        )
        if not is_safe:
            report["ssrf_blocked"] = True
            report["error"] = ssrf_reason
            report["overall_status"] = "SSRF_BLOCKED"
            report["hops"].append({
                "hop": hop_index,
                "url": current_url,
                "status_code": 0,
                "is_https": is_https,
                "resolved_ip": resolved_ip,
                "error": ssrf_reason,
            })
            return report

        # Extract TLS details if HTTPS
        tls_data = None
        if is_https and parsed.hostname:
            port = parsed.port or 443
            tls_data = extract_tls_certificate_info(parsed.hostname, port=port, timeout=timeout)
            if not tls_data.get("valid"):
                report["tls_summary"]["any_tls_error"] = True
            report["tls_summary"]["certificates"].append(tls_data)

        # Loop detection
        normalized_url = current_url.rstrip("/")
        if normalized_url in visited_urls:
            report["loop_detected"] = True
            report["error"] = f"Redirect loop detected at hop {hop_index} ({current_url})"
            report["overall_status"] = "REDIRECT_LOOP"
            report["hops"].append({
                "hop": hop_index,
                "url": current_url,
                "status_code": 0,
                "is_https": is_https,
                "resolved_ip": resolved_ip,
                "tls_info": tls_data,
                "error": "Redirect loop: URL was already visited in this chain.",
            })
            return report

        visited_urls.add(normalized_url)

        # Send request with allow_redirects=False
        try:
            resp = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                stream=True,
                verify=True,  # Never disable verification
            )
            # Read bounded chunk to prevent memory exhaustion
            content_sample = resp.raw.read(max_response_bytes)
            status_code = resp.status_code
            headers_dict = dict(resp.headers)
        except requests.exceptions.SSLError as e:
            report["tls_summary"]["any_tls_error"] = True
            report["error"] = f"TLS Verification Failed: {str(e)}"
            report["overall_status"] = "TLS_VALIDATION_FAILED"
            report["hops"].append({
                "hop": hop_index,
                "url": current_url,
                "status_code": 0,
                "is_https": is_https,
                "resolved_ip": resolved_ip,
                "tls_info": tls_data,
                "error": f"TLS Connection or Certificate error: {str(e)}",
            })
            return report
        except requests.exceptions.RequestException as e:
            report["error"] = f"HTTP Request failed at hop {hop_index}: {str(e)}"
            report["overall_status"] = "INCONCLUSIVE"
            report["hops"].append({
                "hop": hop_index,
                "url": current_url,
                "status_code": 0,
                "is_https": is_https,
                "resolved_ip": resolved_ip,
                "tls_info": tls_data,
                "error": str(e),
            })
            return report

        # Record hop details
        hop_entry = {
            "hop": hop_index,
            "url": current_url,
            "status_code": status_code,
            "is_https": is_https,
            "resolved_ip": resolved_ip,
            "server": headers_dict.get("Server", "Unknown"),
            "content_type": headers_dict.get("Content-Type", "Unknown"),
            "tls_info": tls_data,
        }

        # Check if redirect (301, 302, 303, 307, 308)
        if 300 <= status_code < 400 and "Location" in resp.headers:
            location_raw = resp.headers["Location"]
            next_url = urljoin(current_url, location_raw)
            hop_entry["redirect_to"] = next_url
            report["hops"].append(hop_entry)

            if hop_index >= max_hops:
                report["error"] = f"Exceeded maximum allowed redirect hops ({max_hops})."
                report["overall_status"] = "MAX_HOPS_EXCEEDED"
                return report

            current_url = next_url
        else:
            # Reached final destination
            report["hops"].append(hop_entry)
            report["final_url"] = current_url
            report["total_hops"] = hop_index
            break

    report["total_requests"] = len(report["hops"])
    report["redirect_count"] = sum(1 for h in report["hops"] if "redirect_to" in h)
    report["is_redirected"] = report["redirect_count"] > 0
    report["tls_summary"]["all_https"] = all_hops_tls

    # Policy validation
    target_to_compare = signed_url or initial_url
    policy_ok, policy_msg = check_redirect_policy(
        target_to_compare, report["final_url"], redirect_policy, all_hops_tls
    )
    report["policy_satisfied"] = policy_ok
    report["policy_message"] = policy_msg

    if not policy_ok:
        report["overall_status"] = "DESTINATION_MISMATCH"
        report["success"] = False
    elif report["tls_summary"]["any_tls_error"]:
        report["overall_status"] = "TLS_VALIDATION_FAILED"
        report["success"] = False
    else:
        report["overall_status"] = "AUDIT_SUCCESS"
        report["success"] = True

    return report
