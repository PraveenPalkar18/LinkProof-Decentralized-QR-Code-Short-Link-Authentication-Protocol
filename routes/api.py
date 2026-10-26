"""LinkProof REST API Blueprint for programmatic verification and testing."""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from core.crypto import (
    compute_public_key_fingerprint,
    load_private_key_from_pem,
)
from core.record import (
    build_record_data,
    create_signed_payload,
)
from core.threat_reputation import check_urls_reputation
from core.trust_store import evaluate_linkproof_payload
from models.database import get_verification_stats

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/verify", methods=["POST"])
def api_verify():
    """Programmatic API to verify a LinkProof payload or raw URL."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid or missing JSON body"}), 400

    client_ip = request.remote_addr or "127.0.0.1"

    if "payload" in data:
        payload = data["payload"]
        offline = bool(data.get("offline", False))
        override_pem = data.get("public_key_override")

        result = evaluate_linkproof_payload(
            payload=payload,
            public_key_pem_override=override_pem,
            offline_mode=offline,
            client_ip=client_ip,
        )
        return jsonify({"success": True, "evaluation": result})

    elif "url" in data:
        from core.redirect_checker import inspect_url_redirect_chain
        raw_url = str(data["url"]).strip()
        policy = data.get("redirect_policy", "same_host")
        network_report = inspect_url_redirect_chain(
            initial_url=raw_url,
            redirect_policy=policy,
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
            summary_msg = f"Security Alert: Destination blocked by SSRF defense ({network_report.get('error')})."
        elif network_report.get("loop_detected"):
            status = "REDIRECT_LOOP"
            summary_msg = "Security Warning: Redirect loop detected in URL chain."
        elif not policy_satisfied:
            status = "DESTINATION_MISMATCH"
            summary_msg = f"Security Alert: {network_report.get('policy_message', 'Redirect policy violation.')}"
        elif not tls_valid or network_report.get("tls_summary", {}).get("any_tls_error"):
            status = "TLS_VALIDATION_FAILED"
            summary_msg = f"TLS Security Failure: {network_report.get('error', 'Insecure or invalid TLS certificate encountered.')}"
        elif rep_res["status"] == "THREAT_DETECTED":
            status = "THREAT_DETECTED"
            summary_msg = (
                f"CRITICAL SECURITY ALERT: Google Safe Browsing flagged destination as "
                f"{rep_res.get('threat_category') or rep_res.get('threat_type') or 'MALICIOUS'}. "
                f"This URL is also unauthenticated (no digital signature)."
            )
        elif network_report.get("success"):
            status = "AUDIT_COMPLETE_UNAUTHENTICATED"
            summary_msg = (
                "Network audit completed. This URL was not cryptographically authenticated. "
                "A valid HTTPS certificate does not establish that the website is legitimate or harmless."
            )
        else:
            status = "INCONCLUSIVE"
            summary_msg = f"Network audit inconclusive: {network_report.get('error', 'Inspection incomplete.')}"

        result = {
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
            "summary_message": summary_msg,
        }
        return jsonify({"success": True, "evaluation": result})

    return jsonify({"success": False, "error": "Missing 'payload' or 'url' in JSON body"}), 400


@api_bp.route("/generate", methods=["POST"])
def api_generate():
    """Programmatically sign a record and return the signed payload envelope."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    dest_url = data.get("destination_url")
    issuer_id = data.get("issuer_id")
    priv_pem = data.get("private_key_pem")
    passphrase = data.get("passphrase")
    purpose = data.get("purpose", "")
    policy = data.get("redirect_policy", "same_host")
    expires_at = data.get("expires_at")

    if not dest_url or not priv_pem or not issuer_id:
        return jsonify({"success": False, "error": "Missing required fields: destination_url, issuer_id, private_key_pem"}), 400

    try:
        priv_key = load_private_key_from_pem(priv_pem, passphrase=passphrase or None)
        pub_key = priv_key.public_key()
        fp = compute_public_key_fingerprint(pub_key)

        record_data = build_record_data(
            destination_url=dest_url,
            issuer_id=issuer_id,
            issuer_fingerprint=fp,
            purpose=purpose,
            expires_at=expires_at,
            redirect_policy=policy,
        )
        payload = create_signed_payload(record_data, priv_key)
        return jsonify({"success": True, "payload": payload})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@api_bp.route("/stats", methods=["GET"])
def api_stats():
    """Return JSON verification statistics."""
    stats = get_verification_stats()
    return jsonify({"success": True, "stats": stats})
