"""LinkProof Publisher Blueprint.

Handles ECDSA key generation, passphrase-encrypted storage, record signing,
and high-resolution QR code generation.
"""
from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timedelta, timezone
from flask import (
    Blueprint,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from config import Config
from core.crypto import (
    compute_public_key_fingerprint,
    export_private_key_pem,
    export_public_key_pem,
    generate_key_pair,
    load_private_key_from_pem,
)
from core.qr_service import generate_qr_data_uri, generate_qr_image_bytes
from core.record import (
    RecordValidationError,
    build_record_data,
    create_signed_payload,
)
from core.security import csrf_protect
from models.database import (
    add_trusted_key,
    get_publisher_key_by_id,
    list_publisher_keys,
    save_publisher_key,
)

publisher_bp = Blueprint("publisher", __name__)


@publisher_bp.route("/generate", methods=["GET"])
def generate():
    """Render the QR generation form and publisher key management."""
    keys = list_publisher_keys()
    return render_template(
        "generate.html",
        publisher_keys=keys,
        now_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M"),
        default_expiry=(datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M"),
    )


@publisher_bp.route("/generate/key", methods=["POST"])
@csrf_protect
def create_key():
    """Generate a new ECDSA P-256 key pair protected by a passphrase."""
    issuer_id = request.form.get("issuer_id", "").strip()
    label = request.form.get("label", "").strip()
    passphrase = request.form.get("passphrase", "").strip()
    auto_trust = request.form.get("auto_trust") == "1"

    if not issuer_id:
        flash("Issuer identifier is required.", "danger")
        return redirect(url_for("publisher.generate"))

    if not passphrase or len(passphrase) < 6:
        flash("Passphrase must be at least 6 characters long to protect the private key.", "danger")
        return redirect(url_for("publisher.generate"))

    try:
        priv_key, pub_key = generate_key_pair()
        enc_priv_pem = export_private_key_pem(priv_key, passphrase=passphrase)
        pub_pem = export_public_key_pem(pub_key)
        fingerprint = compute_public_key_fingerprint(pub_key)

        save_publisher_key(
            issuer_id=issuer_id,
            encrypted_private_key_pem=enc_priv_pem,
            public_key_pem=pub_pem,
            fingerprint=fingerprint,
            label=label or f"{issuer_id} signing key",
        )

        if auto_trust:
            add_trusted_key(
                issuer_id=issuer_id,
                public_key_pem=pub_pem,
                fingerprint=fingerprint,
                label=f"Auto-trusted: {label or issuer_id}",
                is_trusted=True,
                notes="Registered automatically during publisher key setup.",
            )
            flash(
                f"Generated key for '{issuer_id}' and automatically registered in Trusted Keys Store! Fingerprint: {fingerprint[:16]}...",
                "success",
            )
        else:
            flash(
                f"Generated ECDSA key for '{issuer_id}'. Fingerprint: {fingerprint[:16]}... Note: Import into Trusted Keys if you wish to verify it locally.",
                "success",
            )

    except Exception as e:
        flash(f"Key generation failed: {str(e)}", "danger")

    return redirect(url_for("publisher.generate"))


@publisher_bp.route("/generate/sign", methods=["POST"])
@csrf_protect
def sign_and_generate():
    """Sign record data and generate the LinkProof QR code."""
    destination_url = request.form.get("destination_url", "").strip()
    issuer_id = request.form.get("issuer_id", "").strip()
    purpose = request.form.get("purpose", "").strip()
    expires_at = request.form.get("expires_at", "").strip()
    redirect_policy = request.form.get("redirect_policy", "same_host")
    key_id = request.form.get("key_id", "").strip()
    custom_pem = request.form.get("custom_private_key_pem", "").strip()
    passphrase = request.form.get("passphrase", "").strip()

    keys = list_publisher_keys()

    if not destination_url:
        flash("Destination URL is required.", "danger")
        return redirect(url_for("publisher.generate"))

    # Obtain private key
    priv_pem_to_use = None
    fingerprint_to_use = None

    if key_id:
        try:
            key_rec = get_publisher_key_by_id(int(key_id))
            if key_rec:
                priv_pem_to_use = key_rec["encrypted_private_key_pem"]
                fingerprint_to_use = key_rec["fingerprint"]
                if not issuer_id:
                    issuer_id = key_rec["issuer_id"]
        except Exception:
            pass

    if not priv_pem_to_use and custom_pem:
        priv_pem_to_use = custom_pem

    if not priv_pem_to_use:
        flash("Please select a stored publisher key or paste a private key PEM.", "danger")
        return redirect(url_for("publisher.generate"))

    try:
        # Decrypt private key
        private_key = load_private_key_from_pem(priv_pem_to_use, passphrase=passphrase or None)
        pub_key = private_key.public_key()
        computed_fp = compute_public_key_fingerprint(pub_key)
        fingerprint = fingerprint_to_use or computed_fp

        # Build canonical record
        record_data = build_record_data(
            destination_url=destination_url,
            issuer_id=issuer_id or "Anonymous-Publisher",
            issuer_fingerprint=fingerprint,
            purpose=purpose,
            expires_at=expires_at if expires_at else None,
            redirect_policy=redirect_policy,
        )

        # Sign record and create payload envelope
        payload = create_signed_payload(record_data, private_key)

        # Generate QR code data URI
        qr_data_uri = generate_qr_data_uri(payload)
        payload_json = json.dumps(payload, indent=2)

        return render_template(
            "generate.html",
            publisher_keys=keys,
            result_payload=payload,
            result_payload_json=payload_json,
            qr_data_uri=qr_data_uri,
            record=record_data,
            now_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M"),
            default_expiry=(datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M"),
        )

    except RecordValidationError as e:
        flash(f"Validation error: {str(e)}", "danger")
    except ValueError as e:
        flash(f"Cryptographic error: {str(e)} (Ensure passphrase is correct)", "danger")
    except Exception as e:
        flash(f"Error signing record: {str(e)}", "danger")

    return redirect(url_for("publisher.generate"))


@publisher_bp.route("/download-qr", methods=["POST"])
@csrf_protect
def download_qr():
    """Download the generated QR code as a PNG file."""
    payload_json = request.form.get("payload_json", "")
    filename = request.form.get("filename", "linkproof-signed-qr.png")

    if not payload_json:
        flash("No payload supplied for download.", "danger")
        return redirect(url_for("publisher.generate"))

    try:
        payload_data = json.loads(payload_json)
        img_bytes = generate_qr_image_bytes(payload_data, image_format="PNG", box_size=10, border=4)
        return send_file(
            io.BytesIO(img_bytes),
            mimetype="image/png",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        flash(f"Failed to generate QR download: {str(e)}", "danger")
        return redirect(url_for("publisher.generate"))
