"""Test suite for core cryptographic operations."""
import pytest
from core.crypto import (
    compute_public_key_fingerprint,
    export_private_key_pem,
    export_public_key_pem,
    format_fingerprint_colon,
    generate_key_pair,
    load_private_key_from_pem,
    load_public_key_from_pem,
    sign_bytes,
    verify_signature,
)


def test_key_pair_generation_and_fingerprint():
    """Verify ECDSA NIST P-256 keygen and SHA-256 fingerprint generation."""
    priv, pub = generate_key_pair()
    assert priv is not None
    assert pub is not None

    fingerprint = compute_public_key_fingerprint(pub)
    assert len(fingerprint) == 64
    assert fingerprint.isupper()

    colon_fp = format_fingerprint_colon(fingerprint)
    assert colon_fp.startswith("SHA256:")
    assert ":" in colon_fp


def test_passphrase_encrypted_pem_storage():
    """Verify private key passphrase encryption and successful decryption."""
    priv, _ = generate_key_pair()
    passphrase = "SecurePassphrase2026!"

    pem_encrypted = export_private_key_pem(priv, passphrase=passphrase)
    assert "ENCRYPTED" in pem_encrypted or "BEGIN PRIVATE KEY" in pem_encrypted

    # Correct passphrase loads key
    loaded_priv = load_private_key_from_pem(pem_encrypted, passphrase=passphrase)
    assert loaded_priv is not None

    # Incorrect passphrase raises error
    with pytest.raises(Exception):
        load_private_key_from_pem(pem_encrypted, passphrase="WrongPassword!")


def test_signing_and_signature_verification():
    """Verify that ECDSA SHA-256 signatures are valid and sensitive to alterations."""
    priv, pub = generate_key_pair()
    message = b"LinkProof CNS Security Project Canonical Record Bytes"

    sig_b64 = sign_bytes(priv, message)
    assert isinstance(sig_b64, str)
    assert len(sig_b64) > 30

    is_valid, msg = verify_signature(pub, sig_b64, message)
    assert is_valid is True
    assert "Valid" in msg

    # Tampered message must fail signature verification
    tampered_msg = b"LinkProof CNS Security Project Canonical Record Bytes TAMPERED"
    is_tampered_valid, reason = verify_signature(pub, sig_b64, tampered_msg)
    assert is_tampered_valid is False
    assert "failed" in reason.lower()

    # Mismatched public key must fail signature verification
    _, another_pub = generate_key_pair()
    is_wrong_key_valid, _ = verify_signature(another_pub, sig_b64, message)
    assert is_wrong_key_valid is False
