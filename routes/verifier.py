"""LinkProof Verifier Blueprint.

Handles QR image uploads, payload parsing, untrusted URL audits,
and renders comprehensive cryptographic & network verification reports.
"""
from __future__ import annotations

import json
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from core.qr_service import decode_qr_image_bytes
from core.redirect_checker import inspect_url_redirect_chain
from core.security import csrf_protect
from core.threat_reputation import check_urls_reputation
from core.trust_store import evaluate_linkproof_payload
from models.database import (
    get_verification_by_id,
    record_verification,
)

verifier_bp = Blueprint("verifier", __name__)


@verifier_bp.route("/verify", methods=["GET"])
def verify_form():
    """Render the primary verification workspace."""
    return render_template("verify.html")


@verifier_bp.route("/verify", methods=["POST"])
@csrf_protect
def verify_submit():
    """Process verification submission via QR image upload, payload text, or raw URL."""
    input_mode = request.form.get("input_mode", "upload")
    offline_mode = request.form.get("offline_mode") == "1"
    pub_key_override = request.form.get("public_key_override", "").strip() or None
    client_ip = request.remote_addr or "127.0.0.1"

    payload_data = None
    raw_url = None

    if input_mode == "upload":
        file = request.files.get("qr_image")
        if not file or not file.filename:
            flash("Please choose a QR code image to upload.", "warning")
            return redirect(url_for("verifier.verify_form"))

        file_bytes = file.read()
        success, raw_text, parsed_json, msg = decode_qr_image_bytes(file_bytes)
        if not success:
            flash(f"QR Decoding Failed: {msg}", "danger")
            return redirect(url_for("verifier.verify_form"))

        if parsed_json:
            payload_data = parsed_json
        elif raw_text:
            if raw_text.startswith("http://") or raw_text.startswith("https://"):
                raw_url = raw_text
            else:
                try:
                    payload_data = json.loads(raw_text)
                except Exception:
                    flash(f"Decoded QR content is neither a LinkProof payload nor a valid URL: '{raw_text[:100]}'", "danger")
                    return redirect(url_for("verifier.verify_form"))

    elif input_mode == "payload":
        payload_text = request.form.get("payload_text", "").strip()
        if not payload_text:
            flash("Please paste a LinkProof JSON payload.", "warning")
            return redirect(url_for("verifier.verify_form"))

        try:
            payload_data = json.loads(payload_text)
        except Exception as e:
            flash(f"Malformed JSON payload: {str(e)}", "danger")
            return redirect(url_for("verifier.verify_form"))

    elif input_mode == "url":
        raw_url = request.form.get("raw_url", "").strip()
        if not raw_url:
            flash("Please enter a URL to audit.", "warning")
            return redirect(url_for("verifier.verify_form"))

    # Case A: Signed LinkProof Payload
    if payload_data:
        eval_result = evaluate_linkproof_payload(
            payload=payload_data,
            public_key_pem_override=pub_key_override,
            offline_mode=offline_mode,
            client_ip=client_ip,
        )
        hist_id = eval_result.get("history_id")
        if hist_id:
            return redirect(url_for("verifier.result_detail", history_id=hist_id))
        else:
            flash("Evaluation completed but failed to generate audit record.", "warning")
            return redirect(url_for("verifier.verify_form"))

    # Case B: Untrusted Raw URL analysis
    elif raw_url:
        if offline_mode:
            flash("Offline mode is not applicable for raw un-signed URLs.", "warning")
            return redirect(url_for("verifier.verify_form"))

        network_report = inspect_url_redirect_chain(
            initial_url=raw_url,
            redirect_policy="same_host",
        )
        final_url = network_report.get("final_url", raw_url)
        tls_valid = (
            network_report.get("tls_summary", {}).get("all_https", False)
            and not network_report.get("tls_summary", {}).get("any_tls_error", False)
        )
        policy_satisfied = network_report.get("policy_satisfied", False)

        # Threat Reputation Evaluation (Google Safe Browsing v4)
        urls_to_check = [raw_url]
        if network_report.get("hops"):
            for h in network_report["hops"]:
                if h.get("url"):
                    urls_to_check.append(h["url"])
                if h.get("redirect_to"):
                    urls_to_check.append(h["redirect_to"])

        rep_res = check_urls_reputation(urls=urls_to_check, offline_mode=False)

        if network_report.get("ssrf_blocked"):
            status = "SSRF_BLOCKED"
            summary_message = f"Security Alert: Destination blocked by SSRF defense ({network_report.get('error')})."
        elif network_report.get("loop_detected"):
            status = "REDIRECT_LOOP"
            summary_message = "Security Warning: Redirect loop detected in URL chain."
        elif not policy_satisfied:
            status = "DESTINATION_MISMATCH"
            summary_message = f"Security Alert: {network_report.get('policy_message', 'Redirect policy violation.')}"
        elif not tls_valid or network_report.get("tls_summary", {}).get("any_tls_error"):
            status = "TLS_VALIDATION_FAILED"
            summary_message = f"TLS Security Failure: {network_report.get('error', 'Insecure or invalid TLS certificate encountered.')}"
        elif rep_res["status"] == "THREAT_DETECTED":
            status = "THREAT_DETECTED"
            summary_message = (
                f"CRITICAL SECURITY ALERT: Google Safe Browsing flagged destination as "
                f"{rep_res.get('threat_category') or rep_res.get('threat_type') or 'MALICIOUS'}. "
                f"This URL is also unauthenticated (no digital signature)."
            )
        elif network_report.get("success"):
            status = "AUDIT_COMPLETE_UNAUTHENTICATED"
            summary_message = (
                "Network audit completed. This URL was not cryptographically authenticated. "
                "A valid HTTPS certificate does not establish that the website is legitimate or harmless."
            )
        else:
            status = "INCONCLUSIVE"
            summary_message = f"Network audit inconclusive: {network_report.get('error', 'Inspection incomplete.')}"

        report_payload = {
            "status": status,
            "overall_status": status,
            "is_raw_url": True,
            "authenticity_status": "NOT_VERIFIED",
            "signature_valid": False,
            "issuer_trusted": False,
            "is_expired": False,
            "is_replay": False,
            "destination_matched": policy_satisfied,
            "tls_valid": tls_valid,
            "network_audit": network_report,
            "threat_reputation": rep_res["status"],
            "threat_reputation_message": rep_res["message"],
            "threat_reputation_result": rep_res,
            "summary_message": summary_message,
        }

        hist_id = record_verification(
            destination_url=raw_url,
            status=status,
            issuer_id="UNTRUSTED_RAW_URL",
            issuer_fingerprint="NONE",
            final_url=final_url,
            signature_valid=False,
            issuer_trusted=False,
            is_expired=False,
            is_replay=False,
            destination_matched=policy_satisfied,
            tls_valid=tls_valid,
            hops_count=network_report.get("total_hops", 0),
            offline_mode=False,
            report_data=report_payload,
            client_ip=client_ip,
        )
        return redirect(url_for("verifier.result_detail", history_id=hist_id))

    flash("No valid input provided.", "warning")
    return redirect(url_for("verifier.verify_form"))


@verifier_bp.route("/result/<int:history_id>")
def result_detail(history_id: int):
    """Display comprehensive verification report and audit trail."""
    record = get_verification_by_id(history_id)
    if not record:
        flash("Verification audit record not found.", "danger")
        return redirect(url_for("dashboard.index"))

    return render_template("result.html", item=record)
