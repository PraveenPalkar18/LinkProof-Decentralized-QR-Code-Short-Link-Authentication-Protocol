"""LinkProof Trusted Keys Management Blueprint."""
from __future__ import annotations

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from core.crypto import (
    compute_public_key_fingerprint,
    format_fingerprint_colon,
    load_public_key_from_pem,
)
from core.security import csrf_protect
from models.database import (
    add_trusted_key,
    delete_trusted_key,
    list_trusted_keys,
    toggle_trusted_key_status,
)

keys_bp = Blueprint("keys", __name__)


@keys_bp.route("/keys", methods=["GET"])
def index():
    """Display all trusted keys with fingerprints and management controls."""
    all_keys = list_trusted_keys()
    # Augment with colon-formatted fingerprints
    for k in all_keys:
        k["fp_colon"] = format_fingerprint_colon(k["fingerprint"])
    return render_template("keys.html", keys=all_keys)


@keys_bp.route("/keys/add", methods=["POST"])
@csrf_protect
def add_key():
    """Import and register a new public key into the trust store."""
    issuer_id = request.form.get("issuer_id", "").strip()
    pem_str = request.form.get("public_key_pem", "").strip()
    label = request.form.get("label", "").strip()
    is_trusted = request.form.get("is_trusted") == "1"
    notes = request.form.get("notes", "").strip()

    if not issuer_id:
        flash("Issuer identifier is required.", "danger")
        return redirect(url_for("keys.index"))

    if not pem_str:
        flash("Public key PEM content is required.", "danger")
        return redirect(url_for("keys.index"))

    try:
        pub_key = load_public_key_from_pem(pem_str)
        fingerprint = compute_public_key_fingerprint(pub_key)

        add_trusted_key(
            issuer_id=issuer_id,
            public_key_pem=pem_str,
            fingerprint=fingerprint,
            label=label or issuer_id,
            is_trusted=is_trusted,
            notes=notes,
        )

        status_word = "TRUSTED" if is_trusted else "UNTRUSTED"
        flash(
            f"Successfully registered {status_word} public key for '{issuer_id}' (Fingerprint: {fingerprint[:16]}...).",
            "success",
        )
    except Exception as e:
        flash(f"Failed to import public key: {str(e)}", "danger")

    return redirect(url_for("keys.index"))


@keys_bp.route("/keys/toggle/<int:key_id>", methods=["POST"])
@csrf_protect
def toggle_status(key_id: int):
    """Toggle a key's trust status between trusted and untrusted."""
    new_status = request.form.get("is_trusted") == "1"
    success = toggle_trusted_key_status(key_id, new_status)
    if success:
        flash(f"Key trust status updated to {'TRUSTED' if new_status else 'UNTRUSTED'}.", "info")
    else:
        flash("Key not found or could not be updated.", "danger")
    return redirect(url_for("keys.index"))


@keys_bp.route("/keys/delete/<int:key_id>", methods=["POST"])
@csrf_protect
def delete_key(key_id: int):
    """Remove a key from the trust store."""
    success = delete_trusted_key(key_id)
    if success:
        flash("Key removed from trust store.", "info")
    else:
        flash("Key could not be deleted.", "danger")
    return redirect(url_for("keys.index"))
