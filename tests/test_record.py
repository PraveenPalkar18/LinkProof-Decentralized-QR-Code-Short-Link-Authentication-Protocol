"""Test suite for LinkProof record canonicalization, schema validation, and expiry."""
import pytest
from core.crypto import generate_key_pair, compute_public_key_fingerprint
from core.record import (
    RecordValidationError,
    build_record_data,
    canonical_serialize,
    check_record_expiry,
    create_signed_payload,
    validate_url,
)


def test_canonical_serialization_determinism():
    """Verify deterministic JSON serialization (keys sorted, no extra whitespace)."""
    data1 = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    data2 = {"c": {"x": 10, "y": 20}, "a": 1, "b": 2}

    ser1 = canonical_serialize(data1)
    ser2 = canonical_serialize(data2)

    assert ser1 == ser2
    assert ser1 == b'{"a":1,"b":2,"c":{"x":10,"y":20}}'


def test_url_validation_allowed_schemes():
    """Verify validation permits only HTTP and HTTPS."""
    validate_url("https://example.com/path")
    validate_url("http://portal.university.edu:8080/test")

    with pytest.raises(RecordValidationError):
        validate_url("javascript:alert(1)")

    with pytest.raises(RecordValidationError):
        validate_url("file:///etc/passwd")

    with pytest.raises(RecordValidationError):
        validate_url("ftp://ftp.example.com")


def test_record_expiration_detection():
    """Verify active vs expired timestamp detection."""
    active_record = {"expires_at": "2099-01-01T00:00:00Z"}
    is_exp, _ = check_record_expiry(active_record)
    assert is_exp is False

    past_record = {"expires_at": "2020-01-01T00:00:00Z"}
    is_exp_past, desc = check_record_expiry(past_record)
    assert is_exp_past is True
    assert "Expired" in desc


def test_invalid_expiry_rejected_at_creation():
    """Verify record creation rejects expiry timestamps earlier than issue timestamps."""
    _, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)

    with pytest.raises(RecordValidationError):
        build_record_data(
            destination_url="https://portal.university.edu",
            issuer_id="cns-dept",
            issuer_fingerprint=fp,
            purpose="Test",
            issued_at="2026-10-25T12:00:00Z",
            expires_at="2026-10-25T11:00:00Z",  # Earlier than issued_at
        )
