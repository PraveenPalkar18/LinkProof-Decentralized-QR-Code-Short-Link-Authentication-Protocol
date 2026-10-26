"""Test suite for QR code generation and OpenCV decoding."""
from core.crypto import compute_public_key_fingerprint, generate_key_pair
from core.qr_service import decode_qr_image_bytes, generate_qr_image_bytes
from core.record import build_record_data, create_signed_payload


def test_qr_generation_and_opencv_decoding_roundtrip():
    """Verify that a signed LinkProof payload survives QR generation and decoding."""
    priv, pub = generate_key_pair()
    fp = compute_public_key_fingerprint(pub)

    record = build_record_data(
        destination_url="https://portal.university.edu/login",
        issuer_id="cns-authority",
        issuer_fingerprint=fp,
        purpose="Official Portal Access",
    )
    payload = create_signed_payload(record, priv)

    # Generate QR PNG bytes
    qr_png = generate_qr_image_bytes(payload)
    assert len(qr_png) > 100
    assert qr_png[:8] == b"\x89PNG\r\n\x1a\n"

    # Decode with OpenCV detector
    success, raw_text, parsed_json, msg = decode_qr_image_bytes(qr_png)
    assert success is True
    assert parsed_json is not None
    assert parsed_json["protocol"] == "linkproof"
    assert parsed_json["record"]["destination_url"] == "https://portal.university.edu/login"
    assert parsed_json["signature"] == payload["signature"]


def test_qr_decoding_malformed_image_fails_safely():
    """Verify that corrupted or empty image bytes do not cause unhandled crashes."""
    success, raw_text, parsed_json, msg = decode_qr_image_bytes(b"not-an-image-data-string")
    assert success is False
    assert parsed_json is None
