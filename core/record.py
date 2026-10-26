"""LinkProof Record Serialization and Validation Module.

Defines the LinkProof Protocol (v1.0) signed record envelope, canonical
JSON serialization (RFC 8785 style), cryptographic binding, and payload validation.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from core.crypto import (
    compute_public_key_fingerprint,
    sign_bytes,
    verify_signature,
    load_public_key_from_pem,
)

PROTOCOL_NAME = "linkproof"
PROTOCOL_VERSION = "1.0"
SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256"

VALID_POLICIES = {
    "strict_exact": "Strict: Destination URL must match final URL exactly (no redirects)",
    "same_host": "Same Host: Redirects allowed only within the exact same hostname",
    "same_registered_domain": "Same Domain: Redirects allowed within the same organization domain",
    "allow_any_tls": "HTTPS Audit: Redirects allowed anywhere if every hop uses valid TLS",
}


class RecordValidationError(ValueError):
    """Raised when record data fails schema or security validation."""
    pass


def canonical_serialize(record_data: Dict[str, Any]) -> bytes:
    """Deterministically serialize a dictionary to canonical JSON bytes.

    Uses sorted keys, UTF-8 encoding, and minimal separators without whitespace.
    """
    return json.dumps(
        record_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def validate_url(url: str) -> None:
    """Validate that a URL is well-formed with an allowed scheme."""
    if not isinstance(url, str) or not url.strip():
        raise RecordValidationError("Destination URL cannot be empty.")
    
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise RecordValidationError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."
        )
    if not parsed.netloc:
        raise RecordValidationError("Destination URL missing valid hostname or authority.")


def parse_iso_datetime(dt_str: str) -> datetime:
    """Parse an ISO-8601 datetime string with UTC handling."""
    if not dt_str or not isinstance(dt_str, str):
        raise RecordValidationError("Datetime string is missing or invalid.")
    try:
        # Standardize 'Z' to '+00:00' for Python 3.11+
        clean_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            # Assume UTC if naive
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception as e:
        raise RecordValidationError(f"Invalid ISO-8601 timestamp '{dt_str}': {str(e)}")


def build_record_data(
    destination_url: str,
    issuer_id: str,
    issuer_fingerprint: str,
    purpose: str,
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    redirect_policy: str = "same_host",
    record_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct and validate the inner record dictionary ready for canonical signing."""
    validate_url(destination_url)

    if not issuer_id or not str(issuer_id).strip():
        raise RecordValidationError("Issuer identifier is required.")

    if not issuer_fingerprint or len(issuer_fingerprint.strip()) < 32:
        raise RecordValidationError("Valid public-key fingerprint is required.")

    if redirect_policy not in VALID_POLICIES:
        raise RecordValidationError(
            f"Invalid redirect policy '{redirect_policy}'. Must be one of: {list(VALID_POLICIES.keys())}"
        )

    now = datetime.now(timezone.utc)
    issue_dt = parse_iso_datetime(issued_at) if issued_at else now
    
    if expires_at:
        exp_dt = parse_iso_datetime(expires_at)
        if exp_dt <= issue_dt:
            raise RecordValidationError("Expiry time must be strictly after issue time.")
    else:
        # Default: 30 days validity
        from datetime import timedelta
        exp_dt = issue_dt + timedelta(days=30)

    rec_id = record_id.strip() if record_id else str(uuid.uuid4())

    return {
        "id": rec_id,
        "issuer_id": issuer_id.strip(),
        "issuer_fingerprint": issuer_fingerprint.strip().upper(),
        "destination_url": destination_url.strip(),
        "purpose": (purpose or "").strip(),
        "issued_at": issue_dt.isoformat().replace("+00:00", "Z"),
        "expires_at": exp_dt.isoformat().replace("+00:00", "Z"),
        "redirect_policy": redirect_policy,
        "sig_alg": SIGNATURE_ALGORITHM,
    }


def create_signed_payload(
    record_data: Dict[str, Any],
    private_key: Any,
) -> Dict[str, Any]:
    """Canonically sign a record dictionary and package into the protocol payload envelope."""
    canonical_bytes = canonical_serialize(record_data)
    signature_b64 = sign_bytes(private_key, canonical_bytes)

    return {
        "protocol": PROTOCOL_NAME,
        "version": PROTOCOL_VERSION,
        "record": record_data,
        "signature": signature_b64,
    }


def verify_payload_signature(
    payload: Dict[str, Any],
    public_key: Any,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Verify the signature and structure of a LinkProof payload using an ECDSA public key.

    Returns (is_valid, message, record_data).
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a JSON object", {}

    if payload.get("protocol") != PROTOCOL_NAME:
        return False, f"Unsupported protocol '{payload.get('protocol')}'. Expected '{PROTOCOL_NAME}'", {}

    if payload.get("version") != PROTOCOL_VERSION:
        return False, f"Unsupported version '{payload.get('version')}'. Expected '{PROTOCOL_VERSION}'", {}

    record = payload.get("record")
    if not isinstance(record, dict):
        return False, "Missing or invalid 'record' dictionary in payload", {}

    signature_b64 = payload.get("signature")
    if not signature_b64 or not isinstance(signature_b64, str):
        return False, "Missing digital signature in payload", record

    # Validate essential fields presence
    required_fields = ["id", "issuer_id", "issuer_fingerprint", "destination_url", "issued_at", "expires_at"]
    for field in required_fields:
        if field not in record:
            return False, f"Missing required record field: '{field}'", record

    # Verify public key fingerprint binding
    key_fingerprint = compute_public_key_fingerprint(public_key)
    record_fp = record.get("issuer_fingerprint", "").replace(":", "").replace(" ", "").upper()
    if record_fp and record_fp != key_fingerprint:
        return (
            False,
            f"Public key fingerprint mismatch. Record claims {record_fp[:16]}... but supplied key is {key_fingerprint[:16]}...",
            record,
        )

    # Perform canonical verification
    canonical_bytes = canonical_serialize(record)
    is_valid, reason = verify_signature(public_key, signature_b64, canonical_bytes)
    return is_valid, reason, record


def check_record_expiry(record: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if the record has expired based on current UTC time.

    Returns (is_expired, status_description).
    """
    try:
        exp_dt = parse_iso_datetime(record.get("expires_at", ""))
        now_utc = datetime.now(timezone.utc)
        if now_utc > exp_dt:
            delta = now_utc - exp_dt
            return True, f"Expired {delta.days} days and {delta.seconds // 3600} hours ago (expired at {exp_dt.isoformat()})"
        return False, f"Valid until {exp_dt.isoformat()}"
    except Exception as e:
        return True, f"Malformed expiration date: {str(e)}"
