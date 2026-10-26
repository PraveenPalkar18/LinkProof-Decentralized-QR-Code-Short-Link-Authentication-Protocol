"""LinkProof Trust Store and Comprehensive Verification Evaluation Engine.

Orchestrates cryptographic verification against trusted public keys,
expiration checks, replay/duplicate detection, and multi-hop network auditing.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from core.crypto import (
    compute_public_key_fingerprint,
    load_public_key_from_pem,
    verify_signature,
)
from core.record import (
    canonical_serialize,
    check_record_expiry,
    verify_payload_signature,
)
from core.redirect_checker import inspect_url_redirect_chain
from core.threat_reputation import check_urls_reputation
from models.database import (
    check_record_replay,
    get_trusted_key_by_fingerprint,
    record_verification,
)


def evaluate_linkproof_payload(
    payload: Dict[str, Any],
    public_key_pem_override: Optional[str] = None,
    offline_mode: bool = False,
    client_ip: Optional[str] = "127.0.0.1",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete end-to-end evaluation of a LinkProof payload.

    Separately assesses:
    1. Payload format & protocol conformance
    2. Digital signature validity
    3. Issuer trust status (via stored trusted public keys)
    4. Expiry status
    5. Replay / duplicate history
    6. Online multi-hop redirect safety, SSRF checks, and TLS validation (unless offline)
    """
    evaluation: Dict[str, Any] = {
        "status": "INCONCLUSIVE",
        "format_valid": False,
        "signature_valid": False,
        "issuer_trusted": False,
        "is_expired": False,
        "is_replay": False,
        "replay_count": 0,
        "first_seen": None,
        "destination_matched": False,
        "tls_valid": False,
        "offline_mode": offline_mode,
        "is_raw_url": False,
        "authenticity_status": "NOT_VERIFIED",
        "threat_reputation": "NOT_CHECKED",
        "threat_reputation_message": "No external threat-intelligence provider configured. Authentic signatures and valid TLS do not prove a website is safe or free of phishing/malware.",
        "record": {},
        "issuer_info": {},
        "network_audit": None,
        "warnings": [],
        "summary_message": "",
        "history_id": None,
    }

    # 1. Format Validation
    if not isinstance(payload, dict):
        evaluation["status"] = "MALFORMED_PAYLOAD"
        evaluation["authenticity_status"] = "NOT_VERIFIED"
        evaluation["summary_message"] = "Submitted payload is not a valid JSON object."
        return evaluation

    record = payload.get("record")
    signature_b64 = payload.get("signature")

    if not isinstance(record, dict) or not signature_b64:
        evaluation["status"] = "MALFORMED_PAYLOAD"
        evaluation["authenticity_status"] = "NOT_VERIFIED"
        evaluation["summary_message"] = "Payload is missing 'record' or 'signature' attributes."
        return evaluation

    evaluation["record"] = record
    evaluation["format_valid"] = True

    record_id = record.get("id")
    issuer_id = record.get("issuer_id", "Unknown")
    claimed_fp = record.get("issuer_fingerprint", "").replace(":", "").replace(" ", "").upper()
    dest_url = record.get("destination_url", "")
    policy = record.get("redirect_policy", "same_host")

    # 2. Replay / Duplicate Check
    is_dup, seen_cnt, first_seen = check_record_replay(record_id, db_path=db_path)
    evaluation["is_replay"] = is_dup
    evaluation["replay_count"] = seen_cnt
    evaluation["first_seen"] = first_seen
    if is_dup:
        evaluation["warnings"].append(
            f"Record ID '{record_id}' was previously verified {seen_cnt} time(s). First seen: {first_seen}."
        )

    # 3. Issuer Trust Determination
    # Look up in trusted keys store
    trusted_key_record = get_trusted_key_by_fingerprint(claimed_fp, db_path=db_path)
    public_key_to_use = None
    is_trusted = False
    is_revoked = False

    if trusted_key_record:
        if trusted_key_record["is_trusted"] == 1:
            is_trusted = True
            evaluation["issuer_info"] = {
                "issuer_id": trusted_key_record["issuer_id"],
                "label": trusted_key_record.get("label", ""),
                "fingerprint": claimed_fp,
                "trusted": True,
                "revoked": False,
            }
            try:
                public_key_to_use = load_public_key_from_pem(trusted_key_record["public_key_pem"])
            except Exception as e:
                evaluation["warnings"].append(f"Could not parse trusted public key: {str(e)}")
        else:
            is_revoked = True
            evaluation["issuer_info"] = {
                "issuer_id": trusted_key_record["issuer_id"],
                "label": trusted_key_record.get("label", ""),
                "fingerprint": claimed_fp,
                "trusted": False,
                "revoked": True,
            }
            evaluation["warnings"].append(
                f"Issuer key '{claimed_fp[:16]}...' is registered in trust store but has been explicitly REVOKED."
            )
            try:
                public_key_to_use = load_public_key_from_pem(trusted_key_record["public_key_pem"])
            except Exception as e:
                evaluation["warnings"].append(f"Could not parse revoked key: {str(e)}")
    else:
        evaluation["warnings"].append(
            f"Unknown Issuer: Public key fingerprint '{claimed_fp[:16]}...' is NOT present in your trusted keys store."
        )

    # If an ad-hoc public key override was supplied, we can verify signature cryptographically
    # but still treat issuer_trusted as False unless it was already in the trusted store!
    if not public_key_to_use and public_key_pem_override:
        try:
            candidate_key = load_public_key_from_pem(public_key_pem_override)
            cand_fp = compute_public_key_fingerprint(candidate_key)
            if cand_fp == claimed_fp:
                public_key_to_use = candidate_key
            else:
                evaluation["warnings"].append(
                    f"Supplied public key fingerprint ({cand_fp[:16]}...) does not match record claimed fingerprint ({claimed_fp[:16]}...)."
                )
        except Exception as e:
            evaluation["warnings"].append(f"Failed to parse override public key PEM: {str(e)}")

    evaluation["issuer_trusted"] = is_trusted

    # 4. Cryptographic Signature Verification
    if public_key_to_use:
        is_sig_valid, sig_reason, _ = verify_payload_signature(payload, public_key_to_use)
        evaluation["signature_valid"] = is_sig_valid
        if not is_sig_valid:
            evaluation["warnings"].append(f"Cryptographic signature check failed: {sig_reason}")
    else:
        evaluation["signature_valid"] = False
        evaluation["warnings"].append("Cannot verify signature: No matching public key available.")

    # 5. Expiry Check
    is_exp, exp_msg = check_record_expiry(record)
    evaluation["is_expired"] = is_exp
    if is_exp:
        evaluation["warnings"].append(f"Record Expiration: {exp_msg}")

    # 6. Network Multi-Hop Redirect & TLS Audit (if not offline mode)
    final_url = dest_url
    if not offline_mode and dest_url:
        network_report = inspect_url_redirect_chain(
            initial_url=dest_url,
            signed_url=dest_url,
            redirect_policy=policy,
        )
        evaluation["network_audit"] = network_report
        final_url = network_report.get("final_url", dest_url)
        evaluation["destination_matched"] = network_report.get("policy_satisfied", False)
        evaluation["tls_valid"] = (
            network_report.get("tls_summary", {}).get("all_https", False)
            and not network_report.get("tls_summary", {}).get("any_tls_error", False)
        )
    else:
        # Offline mode: no network requests
        evaluation["destination_matched"] = True  # Not tested online
        evaluation["tls_valid"] = dest_url.startswith("https://")

    # 6.5 Threat Reputation Evaluation (Google Safe Browsing v4)
    urls_to_check = [dest_url] if dest_url else []
    if not offline_mode and evaluation.get("network_audit"):
        for h in evaluation["network_audit"].get("hops", []):
            if h.get("url"):
                urls_to_check.append(h["url"])
            if h.get("redirect_to"):
                urls_to_check.append(h["redirect_to"])

    rep_res = check_urls_reputation(
        urls=urls_to_check,
        offline_mode=offline_mode,
    )
    evaluation["threat_reputation"] = rep_res["status"]
    evaluation["threat_reputation_message"] = rep_res["message"]
    evaluation["threat_reputation_result"] = rep_res
    if rep_res["status"] == "THREAT_DETECTED":
        evaluation["warnings"].append(
            f"Google Safe Browsing Alert: {rep_res.get('threat_category') or rep_res.get('threat_type')} identified at {rep_res.get('threat_url') or dest_url}."
        )

    # 7. Synthesize Top-Level Status
    if not evaluation["signature_valid"]:
        if not public_key_to_use:
            evaluation["status"] = "UNKNOWN_ISSUER"
            evaluation["authenticity_status"] = "NOT_VERIFIED"
            evaluation["summary_message"] = "Cannot verify record: The issuer's public key is unknown or not trusted."
        else:
            evaluation["status"] = "INVALID_SIGNATURE"
            evaluation["authenticity_status"] = "INVALID"
            evaluation["summary_message"] = "Cryptographic signature is INVALID. The record or destination has been tampered with!"
    elif is_revoked:
        evaluation["status"] = "REVOKED_KEY"
        evaluation["authenticity_status"] = "REVOKED"
        evaluation["summary_message"] = "Issuer key is REVOKED. This record cannot be authenticated."
    elif not evaluation["issuer_trusted"]:
        evaluation["status"] = "UNKNOWN_ISSUER"
        evaluation["authenticity_status"] = "NOT_VERIFIED"
        evaluation["summary_message"] = "Valid signature, but the issuer is UNTRUSTED. Import the issuer's key to trust it."
    elif evaluation["is_expired"]:
        evaluation["status"] = "EXPIRED_RECORD"
        evaluation["authenticity_status"] = "EXPIRED"
        evaluation["summary_message"] = "This record has expired and should not be trusted."
    elif not offline_mode and evaluation["network_audit"]:
        audit = evaluation["network_audit"]
        if audit.get("ssrf_blocked"):
            evaluation["status"] = "SSRF_BLOCKED"
            evaluation["authenticity_status"] = "AUTHENTIC_BUT_NETWORK_BLOCKED"
            evaluation["summary_message"] = f"Security Alert: Destination blocked by SSRF defense ({audit.get('error')})."
        elif audit.get("loop_detected"):
            evaluation["status"] = "REDIRECT_LOOP"
            evaluation["authenticity_status"] = "AUTHENTIC_BUT_NETWORK_FAILED"
            evaluation["summary_message"] = "Security Warning: Redirect loop detected in URL chain."
        elif not evaluation["destination_matched"]:
            evaluation["status"] = "DESTINATION_MISMATCH"
            evaluation["authenticity_status"] = "AUTHENTIC_BUT_POLICY_VIOLATION"
            evaluation["summary_message"] = f"Security Alert: {audit.get('policy_message', 'Destination mismatch detected.')}"
        elif not evaluation["tls_valid"]:
            evaluation["status"] = "TLS_VALIDATION_FAILED"
            evaluation["authenticity_status"] = "AUTHENTIC_BUT_TLS_FAILED"
            evaluation["summary_message"] = f"TLS Security Failure: {audit.get('error', 'Insecure or invalid TLS certificate encountered.')}"
        elif audit.get("success"):
            if rep_res["status"] == "THREAT_DETECTED":
                evaluation["status"] = "THREAT_DETECTED"
                evaluation["authenticity_status"] = "AUTHENTICATED"
                evaluation["summary_message"] = (
                    f"CRITICAL SECURITY ALERT: Destination flagged as {rep_res.get('threat_category') or rep_res.get('threat_type') or 'MALICIOUS'} by Google Safe Browsing. "
                    f"The record signature is authentic from trusted issuer '{issuer_id}', but the target URL contains known threats!"
                )
            else:
                evaluation["status"] = "VERIFIED"
                evaluation["authenticity_status"] = "AUTHENTICATED"
                evaluation["summary_message"] = "VERIFIED: Authentic publisher signature, trusted issuer, safe redirects, and valid TLS."
        else:
            evaluation["status"] = "INCONCLUSIVE"
            evaluation["authenticity_status"] = "INCONCLUSIVE"
            evaluation["summary_message"] = f"Network audit inconclusive: {audit.get('error', 'Inspection incomplete.')}"
    else:
        # Offline verified
        if rep_res["status"] == "THREAT_DETECTED":
            evaluation["status"] = "THREAT_DETECTED"
            evaluation["authenticity_status"] = "AUTHENTICATED"
            evaluation["summary_message"] = (
                f"CRITICAL SECURITY ALERT: Destination flagged as {rep_res.get('threat_category') or 'THREAT'} by Google Safe Browsing. "
                f"Authentic signature by trusted issuer, but target destination is known to be dangerous."
            )
        else:
            evaluation["status"] = "VERIFIED"
            evaluation["authenticity_status"] = "AUTHENTICATED"
            evaluation["summary_message"] = "VERIFIED (Offline): Authentic signature by trusted issuer. Live network checks were not performed."

    # 8. Persist audit to verification history
    try:
        hist_id = record_verification(
            destination_url=dest_url,
            status=evaluation["status"],
            record_id=record_id,
            issuer_id=issuer_id,
            issuer_fingerprint=claimed_fp,
            final_url=final_url,
            signature_valid=evaluation["signature_valid"],
            issuer_trusted=evaluation["issuer_trusted"],
            is_expired=evaluation["is_expired"],
            is_replay=evaluation["is_replay"],
            destination_matched=evaluation["destination_matched"],
            tls_valid=evaluation["tls_valid"],
            hops_count=evaluation["network_audit"].get("total_hops", 0) if evaluation["network_audit"] else 0,
            offline_mode=offline_mode,
            report_data=evaluation,
            client_ip=client_ip,
            db_path=db_path,
        )
        evaluation["history_id"] = hist_id
    except Exception as e:
        evaluation["warnings"].append(f"Failed to record audit trail in database: {str(e)}")

    return evaluation
