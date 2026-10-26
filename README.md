# LinkProof: Decentralized QR Code & Short-Link Authentication Protocol

> **A University Cryptography and Network Security (CNS) Course Capstone Project**  
> Built using **ECDSA NIST P-256**, **SHA-256**, **Multi-Hop TLS Verification**, and **Rigorous SSRF Defense**.

---

## 1. Executive Summary & Problem Definition

### The Security Problem
QR codes and shortened links are ubiquitous in modern physical and digital infrastructure—powering campus portals, electronic ticketing, payment receipts, parking meters, and multi-factor authentication. However, they present significant attack surfaces:

1. **Physical Sticker Replacement (QR Jjacking):** Attackers paste adhesive stickers containing malicious QR codes over legitimate posters, receipts, or signs.
2. **Open Redirects & Chain Manipulation:** A URL may initially target a legitimate domain before hopping through redirects to reach an attacker-controlled credential-harvesting page.
3. **The "HTTPS Illusion":** HTTPS only verifies that an encrypted tunnel exists between the client and whatever server answered the request. It **does not prove** that the destination server is the one authorized or intended by the physical QR publisher. Attackers routinely register lookalike domains with legitimate, free TLS certificates.

### The LinkProof Solution
**LinkProof** introduces a lightweight decentralized authentication layer:
- **Cryptographic Binding:** Publishers generate digitally signed records binding the intended destination URL, issuer identity, timestamps, and approved redirect policies into a canonical envelope.
- **NIST P-256 ECDSA Signatures:** Deterministic canonical JSON serialization signed with ECDSA over SHA-256.
- **Independent Trust Model:** Signature validity is decoupled from key trust. Public keys must be explicitly registered and trusted by the verifier; presenting a key alongside a QR code does not establish authenticity.
- **Multi-Hop Redirect Auditing & SSRF Defense:** Inspects each hop without automatically following redirects, resolves relative locations, verifies TLS certificates, enforces hop limits, and blocks access to internal/private IP ranges (RFC 1918, loopback, link-local, multicast).
- **Offline Signature Verification:** Allows verification without internet access when the publisher's public key is known in advance.

---

## 2. Technology Stack

- **Backend Framework:** Python 3.11+ / Flask 3.1+
- **Cryptography Engine:** Python `cryptography` library (NIST P-256 / secp256r1 ECDSA, SHA-256, PKCS#8 encrypted with AES-256)
- **QR Generation:** `qrcode[pil]`
- **QR Computer Vision Decoding:** OpenCV (`opencv-python-headless` with multi-pass Otsu & adaptive thresholding)
- **Controlled HTTP Client:** `requests` with strict hop-by-hop execution (`allow_redirects=False`)
- **Database:** SQLite 3 (tamper-evident audit trail, trusted keys, publisher key store)
- **Testing Framework:** `pytest` (25 automated test scenarios)
- **Frontend:** Vanilla CSS3 (cybersecurity dark/light design system), HTML5, Jinja2, and Vanilla JavaScript

---

## 3. Cryptographic Protocol Specification (LinkProof v1.0)

### Canonical Record Schema
Every signed QR code or payload contains a versioned JSON envelope:

```json
{
  "protocol": "linkproof",
  "version": "1.0",
  "record": {
    "id": "e4b2f654-7f12-429b-8693-4a1cb5d4918e",
    "issuer_id": "cns.university.edu",
    "issuer_fingerprint": "74E18F4B9131C39ACD9649557C125866AE4D864571A582697EFA4B7CE95C54EF",
    "destination_url": "https://portal.university.edu/admissions",
    "purpose": "Campus Admissions Portal 2026",
    "issued_at": "2026-10-25T12:00:00Z",
    "expires_at": "2026-11-25T12:00:00Z",
    "redirect_policy": "same_host",
    "sig_alg": "ECDSA-P256-SHA256"
  },
  "signature": "MEQCIF+f4G...[Base64 DER Signature]...=="
}
```

### Deterministic Serialization (RFC 8785 Style)
To guarantee that identical dictionary data produces identical signature bytes across different operating systems:
1. Keys are sorted alphabetically (`sort_keys=True`).
2. Separators omit whitespace (`separators=(',', ':')`).
3. Payload is encoded to UTF-8 bytes.
4. Signature is computed exclusively over `canonical_bytes = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')`.

### Public Key Fingerprint Binding
Public keys are identified by their **SHA-256 fingerprint** computed over `SubjectPublicKeyInfo` DER bytes:
$$\text{Fingerprint} = \text{SHA256}(\text{DER}_{\text{SubjectPublicKeyInfo}})$$
The fingerprint is embedded inside the signed record itself, cryptographically binding the record to the intended public key and preventing key substitution attacks.

### Approved Redirect Policies
- `strict_exact`: Final landing URL must match the signed `destination_url` character-for-character (no redirects allowed).
- `same_host`: Redirects are allowed only within the exact same hostname/domain.
- `same_registered_domain`: Redirects are allowed across subdomains of the same registrable domain.
- `allow_any_tls`: Redirects may travel to any domain provided every intermediate hop and final target uses valid TLS.

---

## 4. Multi-Hop Redirect & SSRF Defense Architecture

When online verification is performed, LinkProof executes an active security audit:

```
[Initial URL]
      │
      ▼
┌──────────────────────────────────────────────┐
│ 1. Scheme Check (Only HTTP / HTTPS permitted)│
└──────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────┐
│ 2. Pre-Hop DNS Resolution                    │
│    Resolve hostname to IPv4/IPv6 addresses   │
└──────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────┐
│ 3. SSRF & Address Boundary Filter            │
│    BLOCK: 127.0.0.0/8 (Loopback, ::1)        │
│    BLOCK: 10.0.0.0/8, 172.16.0.0/12,         │
│           192.168.0.0/16 (RFC 1918 Private)  │
│    BLOCK: 169.254.0.0/16 (Link-Local/APIPA)  │
│    BLOCK: Multicast, Broadcast, 0.0.0.0/8    │
└──────────────────────────────────────────────┘
      │ Safe
      ▼
┌──────────────────────────────────────────────┐
│ 4. Single-Hop Request (allow_redirects=False)│
│    Capture Status Code, Headers, TLS Cert    │
└──────────────────────────────────────────────┘
      │
      ├─ 3xx Redirect ──> Extract Location Header ──> Loop & Hop Limit Check ──> (Repeat Step 1)
      │
      └─ 200 OK ────────> Verify Redirect Policy Compliance against Signed Record
```

---

## 5. Verification Status States

LinkProof strictly decouples cryptographic authenticity, identity trust, and network auditing:

| Status Badge | Cryptographic Meaning | Network & Trust Finding |
| :--- | :--- | :--- |
| **`THREAT_DETECTED`** | **Critical Security Alert.** | Third-party threat intelligence (Google Safe Browsing) flags URL as **Phishing, Malware, or Unwanted Software**. |
| **`VERIFIED`** | Signature is mathematically valid. | Issuer is trusted and active, record is unexpired, and redirect policy is satisfied. |
| **`AUDIT_COMPLETE_UNAUTHENTICATED`** | **Not authenticated (Raw URL).** | Network redirects, TLS, and SSRF checks completed, but URL lacks a cryptographic signature. |
| **`REVOKED_KEY`** | Signature may be valid. | The signing key has been explicitly **revoked** in the verifier's trust store. |
| **`INVALID_SIGNATURE`** | Cryptographic signature verification failed. | The payload bytes or destination URL have been tampered with. |
| **`UNKNOWN_ISSUER`** | Signature valid, but key untrusted. | Public key fingerprint is not present in local trusted keys store. |
| **`EXPIRED_RECORD`** | Signature valid, issuer trusted. | Current UTC time exceeds `expires_at` timestamp. |
| **`DESTINATION_MISMATCH`**| Signature valid, issuer trusted. | Multi-hop redirects terminated at an unauthorized foreign destination. |
| **`TLS_VALIDATION_FAILED`**| Signature valid or raw URL. | Unencrypted HTTP detected or target TLS certificate is untrusted/expired. |
| **`SSRF_BLOCKED`** | Security violation flagged immediately. | Outbound redirect attempted connection to a loopback or private IP. |
| **`MALFORMED_PAYLOAD`**| Unusable data format. | Payload is missing required attributes or contains invalid JSON. |
| **`INCONCLUSIVE`** | Incomplete inspection. | Network timeout or DNS failure prevented verification completion. |

> [!IMPORTANT]
> **Threat Reputation States (Google Safe Browsing API v4):**
> - **`THREAT_DETECTED`**: Provider flagged the URL or an intermediate redirect hop as Malware, Phishing/Social Engineering, or Unwanted Software.
> - **`NO_KNOWN_THREAT`**: No threat was identified by Google Safe Browsing. *Note: This does not guarantee the URL is completely safe or authentic.*
> - **`NOT_CHECKED`**: Threat lookup was not executed (e.g. offline mode requested, or `GOOGLE_SAFE_BROWSING_API_KEY` is unset).
> - **`CHECK_UNAVAILABLE`**: Threat lookup could not be completed (e.g. network timeout, provider HTTP error, or quota limit). Never treated as clean.


## 6. Threat Model & Security Assumptions

1. **Decoupling Mathematical Authenticity from Identity Trust & Threat Reputation:**
   Possessing a mathematically valid ECDSA signature only proves that whoever held the corresponding private key produced the signature. A positive reputation result never makes an invalid signature valid or an untrusted issuer trusted. Conversely, an authentic record pointing to a phishing page triggers a critical `THREAT_DETECTED` security alert.
2. **Offline Verification Limitations:**
   Offline clients can verify signatures against previously installed trusted keys. However, offline clients **cannot detect real-time key revocations** until their local trust store is synchronized.
3. **Private Key Protection at Rest:**
   Publisher private keys are encrypted on disk using PKCS#8 `BestAvailableEncryption` (AES-256) with a user-supplied passphrase. Decrypted keys are held in memory only for the duration of the signing operation and are never exposed via HTTP responses or log files.
4. **Defense-in-Depth against DNS Rebinding:**
   Hostnames are resolved to IP addresses and evaluated against the SSRF filter before **every individual redirect hop**, preventing attackers from using dynamic DNS records to pivot into internal cloud services.

---

## 7. Installation & Quickstart (Windows PowerShell)

### Prerequisites
- Python 3.11 or higher
- Windows PowerShell

### Step-by-Step Setup

```powershell
# 1. Clone or navigate to the project directory
cd "e:\VII'\CNS\LinkProof"

# 2. Create the Python virtual environment
python -m venv venv

# 3. Activate the virtual environment
.\venv\Scripts\Activate.ps1

# 4. Install all dependencies
pip install -r requirements.txt

# 5. (Optional) Configure Google Safe Browsing Threat Intelligence API
# To avoid echoing your secret key into PowerShell command history or terminal logs, use Read-Host:
$env:GOOGLE_SAFE_BROWSING_API_KEY = (Read-Host -AsSecureString "Enter Google Safe Browsing API Key" | [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)))

# Alternatively, set it directly for the current PowerShell session only:
# $env:GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSy..."

# 6. Execute the automated test suite (all tests use mocked provider responses)
pytest -v

# 7. Start the LinkProof application
python app.py
```

Open your browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

### Testing Google Safe Browsing Integration
- When `$env:GOOGLE_SAFE_BROWSING_API_KEY` is not set:
  - Audits show Check 8 with badge **`NOT_CHECKED`** ("Provider not configured").
- When a valid key is set:
  - Clean URLs (e.g. `https://example.com`) display **`NO_KNOWN_THREAT`** ("No threats reported by Google Safe Browsing").
  - Test threat URLs (e.g. `https://testsafebrowsing.appspot.com/s/phishing.html` or `malware.html`) display **`THREAT_DETECTED`** ("Critical Security Alert: Social Engineering / Phishing identified").

---

## 8. Automated Test Results

The project includes **57 comprehensive automated tests** across cryptographic, network, web, and threat intelligence suites:

```text
tests/test_crypto.py::test_key_pair_generation_and_fingerprint PASSED        [  1%]
tests/test_crypto.py::test_passphrase_encrypted_pem_storage PASSED           [  3%]
tests/test_crypto.py::test_signing_and_signature_verification PASSED         [  5%]
tests/test_qr.py::test_qr_generation_and_opencv_decoding_roundtrip PASSED     [  7%]
tests/test_qr.py::test_qr_decoding_malformed_image_fails_safely PASSED       [  8%]
tests/test_record.py::test_canonical_serialization_determinism PASSED        [ 10%]
tests/test_record.py::test_url_validation_allowed_schemes PASSED             [ 12%]
tests/test_record.py::test_record_expiration_detection PASSED                [ 14%]
tests/test_record.py::test_invalid_expiry_rejected_at_creation PASSED        [ 15%]
tests/test_redirect_ssrf.py::test_ssrf_ip_filter_blocks_unsafe_addresses PASSED [ 17%]
tests/test_redirect_ssrf.py::test_redirect_policy_enforcement PASSED         [ 19%]
tests/test_redirect_ssrf.py::test_relative_redirect_resolution PASSED        [ 21%]
tests/test_redirect_ssrf.py::test_redirect_loop_detection PASSED             [ 22%]
tests/test_redirect_ssrf.py::test_ssrf_blocks_redirect_to_private_address PASSED [ 24%]
tests/test_redirect_ssrf.py::test_redirect_count_distinguishes_initial_from_redirects PASSED [ 26%]
tests/test_regression_verdict.py::test_raw_url_http_200_valid_tls_not_marked_verified PASSED [ 28%]
tests/test_regression_verdict.py::test_raw_url_with_satisfied_redirect_policy_remains_unauthenticated PASSED [ 29%]
tests/test_regression_verdict.py::test_raw_url_with_invalid_tls_not_marked_authenticated PASSED [ 31%]
tests/test_regression_verdict.py::test_valid_signature_and_trusted_issuer_succeeds PASSED [ 33%]
tests/test_regression_verdict.py::test_tampered_destination_url_fails_signature PASSED [ 35%]
tests/test_regression_verdict.py::test_invalid_signature_plus_untrusted_issuer_rejected PASSED [ 36%]
tests/test_regression_verdict.py::test_unknown_issuer_cannot_be_authenticated PASSED [ 38%]
tests/test_regression_verdict.py::test_revoked_issuer_key_cannot_be_authenticated PASSED [ 40%]
tests/test_regression_verdict.py::test_expired_signed_record_cannot_be_authenticated PASSED [ 42%]
tests/test_regression_verdict.py::test_malformed_payload_and_signature_rejected_safely PASSED [ 43%]
tests/test_regression_verdict.py::test_redirect_policy_violation_cannot_produce_authenticated_success PASSED [ 45%]
tests/test_regression_verdict.py::test_ssrf_blocked_requests_not_reported_as_success PASSED [ 47%]
tests/test_regression_verdict.py::test_missing_threat_intelligence_is_not_checked PASSED [ 49%]
tests/test_regression_verdict.py::test_dashboard_metrics_do_not_count_unauthenticated_raw_audits PASSED [ 50%]
tests/test_regression_verdict.py::test_exceptions_or_missing_fields_never_default_to_verified PASSED [ 52%]
tests/test_threat_reputation.py::test_url_normalization_handles_various_formats PASSED [ 54%]
tests/test_threat_reputation.py::test_missing_api_key_returns_not_checked PASSED [ 56%]
tests/test_threat_reputation.py::test_offline_mode_returns_not_checked PASSED [ 57%]
tests/test_threat_reputation.py::test_no_known_threat_reported PASSED        [ 59%]
tests/test_threat_reputation.py::test_phishing_social_engineering_detected PASSED [ 61%]
tests/test_threat_reputation.py::test_malware_detected PASSED                [ 63%]
tests/test_threat_reputation.py::test_api_timeout_returns_check_unavailable PASSED [ 64%]
tests/test_threat_reputation.py::test_quota_limit_429_returns_check_unavailable PASSED [ 66%]
tests/test_threat_reputation.py::test_http_500_error_returns_check_unavailable PASSED [ 68%]
tests/test_threat_reputation.py::test_malformed_json_response_returns_check_unavailable PASSED [ 70%]
tests/test_threat_reputation.py::test_threat_detected_does_not_override_signature_failure PASSED [ 71%]
tests/test_threat_reputation.py::test_threat_detected_does_not_make_untrusted_issuer_trusted PASSED [ 73%]
tests/test_threat_reputation.py::test_authentic_record_with_threat_flagged_as_threat_detected PASSED [ 75%]
tests/test_threat_reputation.py::test_raw_url_audit_with_phishing_detected_returns_threat_detected PASSED [ 77%]
tests/test_threat_reputation.py::test_deduplication_of_urls_in_reputation_query PASSED [ 78%]
tests/test_verifier.py::test_legitimate_signed_qr_record_verifies PASSED     [ 80%]
tests/test_verifier.py::test_destination_tampering_invalidates_signature PASSED [ 82%]
tests/test_verifier.py::test_unknown_issuer_not_automatically_trusted PASSED [ 84%]
tests/test_verifier.py::test_expired_record_identified PASSED                [ 85%]
tests/test_verifier.py::test_malformed_payload_rejected_safely PASSED        [ 87%]
tests/test_verifier.py::test_replay_duplicate_detection PASSED               [ 89%]
tests/test_web.py::test_public_pages_render_successfully PASSED              [ 91%]
tests/test_web.py::test_security_headers_present PASSED                      [ 92%]
tests/test_web.py::test_csrf_protection_rejects_unauthenticated_post PASSED   [ 94%]
tests/test_web.py::test_private_keys_not_exposed_in_responses PASSED         [ 96%]
tests/test_web.py::test_api_generate_and_verify PASSED                       [ 98%]
tests/test_web.py::test_web_raw_url_audit_html_renders_unauthenticated PASSED [100%]

============================= 57 passed in 4.71s ===============================
```

---

## 9. University Viva & Live Demonstration Walkthrough

When presenting this project to an examiner or professor, follow this demonstration script:

### Step 1: Publisher Key Setup & Fingerprint Inspection
1. Navigate to **Generate Signed QR** (`/generate`).
2. Under **Generate Publisher Key Pair**, enter:
   - Issuer: `cns.university.edu`
   - Label: `Official Campus Key 2026`
   - Passphrase: `SecurePassphrase123!`
   - Ensure *Automatically register in Trusted Keys store* is checked.
3. Click **Generate & Save ECDSA Key**.
4. Point out the SHA-256 fingerprint generated over the public key.

### Step 2: Issue an ECDSA-Signed QR Code
1. In the **Create Signed QR Code** form, specify:
   - Destination URL: `https://portal.university.edu/admissions`
   - Issuer: `cns.university.edu`
   - Purpose: `Admissions Portal Access`
   - Redirect Policy: `Same Host`
   - Enter the key passphrase: `SecurePassphrase123!`
2. Click **Sign Record & Generate QR Code**.
3. Inspect the resulting preview:
   - Point out the QR Code generated using high-contrast modules.
   - Click **Download QR PNG Image**.
   - Show the canonical JSON payload with its Base64 DER signature.

### Step 3: Verify the Authentic QR Code
1. Click **Test & Verify This QR Payload** (or navigate to `/verify` and upload the downloaded PNG image).
2. Check the **Offline Signature Verification Only** checkbox (to test local crypto first).
3. Click **Verify Authenticity & Audit Redirect Chain**.
4. The audit report immediately shows **`VERIFIED (Offline)`**:
   - Signature: Valid ✓
   - Issuer Trust: Trusted ✓
   - Expiration: Active ✓
   - Replay: First Seen ✓

### Step 4: Demonstrate Tampering Detection (Attacker Simulation)
1. Go to `/verify` and select the **Paste Signed Payload** tab.
2. Paste the legitimate payload from Step 2.
3. Modify the destination URL from `https://portal.university.edu/admissions` to `https://evil-phishing.com`.
4. Click **Verify Authenticity**.
5. The application immediately displays **`INVALID SIGNATURE`** in glowing crimson, proving that any alteration to the destination URL invalidates the ECDSA signature.

### Step 5: Demonstrate Untrusted Issuer Attack
1. Go to `/keys` and click **Mark Untrusted** on the `cns.university.edu` key.
2. Return to `/verify` and verify the legitimate payload again.
3. The application displays **`UNKNOWN ISSUER`** (Warning state), demonstrating that a mathematically valid signature signed by an untrusted key is never trusted.

### Step 6: Demonstrate SSRF Protection
1. Go to `/verify`, select **Audit Untrusted Link**, and enter: `http://127.0.0.1:8080/internal-secrets` or `http://169.254.169.254/latest/meta-data/`.
2. Click **Verify Authenticity**.
3. LinkProof halts immediately with **`SSRF BLOCKED`**, explaining that outbound connections to loopback and link-local addresses are strictly prohibited.

---

## 10. Repository File Structure

```
LinkProof/
├── app.py                     # Application entry point & factory
├── config.py                  # Security limits, paths, algorithms
├── requirements.txt           # Python dependency specifications
├── .env.example               # Configuration template
├── .gitignore                 # Excludes secrets, keys, and DBs
├── README.md                  # Comprehensive CNS documentation
├── core/
│   ├── crypto.py              # ECDSA P-256 keygen, PEM AES-256, SHA-256 fingerprints
│   ├── record.py              # Canonical JSON serialization & payload envelope
│   ├── qr_service.py          # QR generation (PIL) & decoding (OpenCV)
│   ├── redirect_checker.py    # Multi-hop safe redirects, SSRF blocker, TLS audit
│   ├── threat_reputation.py   # Google Safe Browsing API v4 threat intelligence
│   ├── security.py            # CSRF protection & security decorators
│   └── trust_store.py         # Trust evaluation & audit orchestrator
├── models/
│   └── database.py            # SQLite schema, queries, audit logging, replay checks
├── routes/
│   ├── dashboard.py           # Real-time metrics & recent activity
│   ├── publisher.py           # Key management, signing & QR download
│   ├── verifier.py            # QR file upload, payload parsing, audit reports
│   ├── keys.py                # Trusted keys store management
│   ├── about.py               # Threat model & protocol documentation
│   └── api.py                 # REST API endpoints
├── static/
│   ├── css/style.css          # Cybersecurity theme, badges, timelines
│   └── js/main.js             # Theme toggle, clipboard, drag-and-drop
├── templates/
│   ├── base.html              # Base layout with navbar & theme toggle
│   ├── dashboard.html         # Live KPI cards & recent verification log
│   ├── generate.html          # Publisher key setup & signed QR generator
│   ├── verify.html            # Verification hub (Upload / Paste / URL)
│   ├── result.html            # Verification audit report & redirect timeline
│   ├── keys.html              # Trusted keys management
│   ├── about.html             # Threat model, protocol & SSRF documentation
│   └── error.html             # Safe error page (no stack traces)
└── tests/
    ├── test_crypto.py         # ECDSA keygen, AES-256 PEM, signature tampering
    ├── test_record.py         # Canonical serialization & expiration tests
    ├── test_qr.py             # QR generation & OpenCV decoding roundtrip
    ├── test_redirect_ssrf.py  # SSRF filter, loops, relative redirects, policy
    ├── test_threat_reputation.py # Google Safe Browsing API mocking & state tests
    ├── test_verifier.py       # End-to-end evaluation & replay detection
    └── test_web.py            # Route integration, CSRF, security headers
```

---

## 11. Academic Course Project Attribution

- **Course:** Cryptography and Network Security (CNS)
- **Topic:** Decentralized Authentication Protocols & PKI
- **Protocol:** LinkProof Protocol v1.0
- **Implementation Status:** Fully functional, locally tested, 100% test pass rate.
