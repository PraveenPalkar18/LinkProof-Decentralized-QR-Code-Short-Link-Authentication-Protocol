"""LinkProof Cryptographic Module.

Provides ECDSA (NIST P-256 / secp256r1) key generation, passphrase-based
PEM encryption, SHA-256 public-key fingerprinting, and deterministic
digital signature generation and verification.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Tuple, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)


def generate_key_pair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECDSA P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def export_private_key_pem(
    private_key: EllipticCurvePrivateKey,
    passphrase: Optional[str] = None,
) -> str:
    """Serialize private key to PEM format.

    Uses passphrase-based encryption (AES-256) when a passphrase is provided.
    """
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        )
    else:
        encryption_algorithm = serialization.NoEncryption()

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    return pem_bytes.decode("ascii")


def load_private_key_from_pem(
    pem_str: str,
    passphrase: Optional[str] = None,
) -> EllipticCurvePrivateKey:
    """Load an ECDSA private key from PEM string, decrypting with passphrase if encrypted."""
    pw_bytes = passphrase.encode("utf-8") if passphrase else None
    private_key = serialization.load_pem_private_key(
        pem_str.encode("ascii"),
        password=pw_bytes,
    )
    if not isinstance(private_key, EllipticCurvePrivateKey):
        raise ValueError("Loaded key is not an EllipticCurvePrivateKey.")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("Curve must be NIST P-256 (secp256r1).")
    return private_key


def export_public_key_pem(public_key: EllipticCurvePublicKey) -> str:
    """Export public key in SubjectPublicKeyInfo PEM format."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


def load_public_key_from_pem(pem_str: str) -> EllipticCurvePublicKey:
    """Load an ECDSA public key from PEM string and ensure it is NIST P-256."""
    public_key = serialization.load_pem_public_key(pem_str.strip().encode("ascii"))
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise ValueError("Loaded key is not an EllipticCurvePublicKey.")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("Curve must be NIST P-256 (secp256r1).")
    return public_key


def compute_public_key_fingerprint(public_key: EllipticCurvePublicKey) -> str:
    """Compute the SHA-256 fingerprint over SubjectPublicKeyInfo DER bytes.

    Returns a 64-character uppercase hexadecimal digest.
    """
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest().upper()


def format_fingerprint_colon(hex_digest: str) -> str:
    """Format a 64-char hex string as COLON-separated pairs (e.g. SHA256:AA:BB:CC...)."""
    clean_hex = hex_digest.replace(":", "").replace(" ", "").upper()
    pairs = [clean_hex[i : i + 2] for i in range(0, len(clean_hex), 2)]
    return "SHA256:" + ":".join(pairs)


def sign_bytes(private_key: EllipticCurvePrivateKey, data: bytes) -> str:
    """Sign arbitrary data bytes using ECDSA with SHA-256.

    Returns a Base64-encoded ASN.1 DER signature string.
    """
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(der_signature).decode("ascii")


def verify_signature(
    public_key: EllipticCurvePublicKey,
    signature_b64: str,
    data: bytes,
) -> Tuple[bool, str]:
    """Verify an ECDSA SHA-256 signature against data bytes.

    Returns (is_valid, reason_or_status).
    """
    try:
        der_signature = base64.b64decode(signature_b64.encode("ascii"))
    except Exception as e:
        return False, f"Malformed Base64 signature: {str(e)}"

    try:
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True, "Valid ECDSA P-256 signature"
    except InvalidSignature:
        return False, "Digital signature verification failed (tampered data or mismatched key)"
    except Exception as e:
        return False, f"Verification error: {str(e)}"
