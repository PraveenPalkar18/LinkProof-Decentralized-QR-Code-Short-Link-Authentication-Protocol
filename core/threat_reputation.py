"""LinkProof Threat Reputation Engine.

Integrates with the Google Safe Browsing API v4 (threatMatches:find) to detect
malware, phishing/social engineering, unwanted software, and potentially
harmful applications across submitted destinations and validated redirect chains.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse, urlunparse

import requests

from config import Config

logger = logging.getLogger("linkproof.threat_reputation")

# Supported Safe Browsing threat categories
SUPPORTED_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Google Safe Browsing v4 endpoint
SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def get_api_key() -> Optional[str]:
    """Retrieve the Google Safe Browsing API key from environment or config.
    
    Ensures keys are never hardcoded or exposed in logs.
    Prioritizes current_app.config when in Flask context (allowing TestConfig overrides).
    """
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            key = current_app.config.get("GOOGLE_SAFE_BROWSING_API_KEY", None)
            if key is not None:
                return key.strip() or None
    except Exception:
        pass

    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not key and hasattr(Config, "GOOGLE_SAFE_BROWSING_API_KEY"):
        key = getattr(Config, "GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    return key or None


def normalize_url_for_lookup(url: str) -> Optional[str]:
    """Normalize a URL for Google Safe Browsing query without mutating signed records.

    Applies RFC 3986 normalization:
    - Strips whitespace.
    - Lowers scheme and hostname.
    - Removes standard default ports (:80, :443).
    - Ensures path has at least a leading slash.
    """
    if not url or not isinstance(url, str):
        return None

    cleaned = url.strip()
    try:
        parsed = urlparse(cleaned)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return None

        hostname = parsed.hostname
        if not hostname:
            return None
        hostname = hostname.lower()

        port = parsed.port
        # Drop redundant default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = hostname
        elif port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            ""  # Exclude fragment per Safe Browsing guidelines
        ))
        return normalized
    except Exception:
        return cleaned


def query_google_safe_browsing(
    urls: List[str],
    api_key: str,
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Execute threatMatches:find lookup against Google Safe Browsing API v4.

    Never logs the API key or includes the key in exception messages.
    """
    if not urls:
        return {
            "status": "NOT_CHECKED",
            "threat_type": None,
            "threat_url": None,
            "message": "No URLs provided for threat reputation lookup.",
            "details": {},
        }

    # Bounded payload: up to 10 unique URLs per single audit
    unique_urls = list(dict.fromkeys(urls))[:10]

    request_body = {
        "client": {
            "clientId": "linkproof-protocol",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": SUPPORTED_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in unique_urls],
        },
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "LinkProof-Protocol/1.0",
    }

    try:
        # Pass API key strictly via URL query parameter as required by Google Safe Browsing
        response = requests.post(
            SAFE_BROWSING_API_URL,
            params={"key": api_key},
            json=request_body,
            headers=headers,
            timeout=timeout,
        )

        # Quota limit (HTTP 429)
        if response.status_code == 429:
            return {
                "status": "CHECK_UNAVAILABLE",
                "threat_type": None,
                "threat_url": None,
                "message": "Google Safe Browsing quota exceeded (HTTP 429). Threat reputation check temporarily unavailable.",
                "details": {"http_status": 429},
            }

        # Client / Server HTTP Error (4xx, 5xx)
        if response.status_code != 200:
            return {
                "status": "CHECK_UNAVAILABLE",
                "threat_type": None,
                "threat_url": None,
                "message": f"Google Safe Browsing service returned error (HTTP {response.status_code}). Threat reputation could not be verified.",
                "details": {"http_status": response.status_code},
            }

        data = response.json()
        matches = data.get("matches", [])

        if matches:
            # Threat detected! Extract primary match details
            first_match = matches[0]
            threat_type = first_match.get("threatType", "MALWARE")
            matched_url = first_match.get("threat", {}).get("url")

            # Human-readable threat category label
            category_names = {
                "MALWARE": "Malware / Exploit",
                "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
                "UNWANTED_SOFTWARE": "Unwanted Software",
                "POTENTIALLY_HARMFUL_APPLICATION": "Harmful Application",
            }
            readable_category = category_names.get(threat_type, threat_type)

            return {
                "status": "THREAT_DETECTED",
                "threat_type": threat_type,
                "threat_category": readable_category,
                "threat_url": matched_url,
                "all_matches": matches,
                "message": f"Google Safe Browsing identified {readable_category} on destination: {matched_url or 'target URL'}.",
                "details": data,
            }

        # Clean report (no known threats reported)
        return {
            "status": "NO_KNOWN_THREAT",
            "threat_type": None,
            "threat_url": None,
            "message": "No known threats reported by Google Safe Browsing. (Note: Valid reputation does not guarantee the website is completely harmless).",
            "details": data,
        }

    except requests.exceptions.Timeout:
        return {
            "status": "CHECK_UNAVAILABLE",
            "threat_type": None,
            "threat_url": None,
            "message": f"Google Safe Browsing request timed out after {timeout}s. Threat reputation could not be determined.",
            "details": {"error": "Timeout"},
        }
    except requests.exceptions.RequestException as e:
        # Sanitize any potential query params or secrets from exception string
        err_msg = re.sub(r"key=[^&\s]+", "key=[REDACTED]", str(e))
        return {
            "status": "CHECK_UNAVAILABLE",
            "threat_type": None,
            "threat_url": None,
            "message": f"Network error connecting to threat intelligence provider: {err_msg}",
            "details": {"error": "RequestException"},
        }
    except ValueError as e:
        # JSON decode failure
        return {
            "status": "CHECK_UNAVAILABLE",
            "threat_type": None,
            "threat_url": None,
            "message": "Malformed response returned by Google Safe Browsing API.",
            "details": {"error": "JSONDecodeError"},
        }


def check_urls_reputation(
    urls: Union[str, List[str]],
    api_key: Optional[str] = None,
    offline_mode: bool = False,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Evaluate reputation for a target URL and optional redirect hops.

    Returns structured reputation result with guaranteed fields:
    - status: THREAT_DETECTED | NO_KNOWN_THREAT | NOT_CHECKED | CHECK_UNAVAILABLE
    - threat_type: Optional[str] (e.g. SOCIAL_ENGINEERING, MALWARE)
    - threat_category: Optional[str]
    - threat_url: Optional[str]
    - message: str
    - checked_urls: List[str]
    - provider: str
    """
    effective_timeout = timeout or getattr(Config, "SAFE_BROWSING_TIMEOUT_SECONDS", 4.0)

    # 1. Offline Mode Guard
    if offline_mode:
        return {
            "status": "NOT_CHECKED",
            "threat_type": None,
            "threat_category": None,
            "threat_url": None,
            "message": "Offline audit mode active. External threat-intelligence lookups were skipped.",
            "checked_urls": [],
            "provider": "None",
            "details": {},
        }

    # 2. Check API Key
    key_to_use = api_key or get_api_key()
    if not key_to_use:
        return {
            "status": "NOT_CHECKED",
            "threat_type": None,
            "threat_category": None,
            "threat_url": None,
            "message": "Google Safe Browsing API key not configured (GOOGLE_SAFE_BROWSING_API_KEY unset). Threat reputation was not checked.",
            "checked_urls": [],
            "provider": "Google Safe Browsing v4",
            "details": {},
        }

    # 3. Normalize & Deduplicate URLs
    input_urls = [urls] if isinstance(urls, str) else urls
    normalized_urls: List[str] = []
    seen: Set[str] = set()

    for u in input_urls:
        norm = normalize_url_for_lookup(u)
        if norm and norm not in seen:
            seen.add(norm)
            normalized_urls.append(norm)

    if not normalized_urls:
        return {
            "status": "NOT_CHECKED",
            "threat_type": None,
            "threat_category": None,
            "threat_url": None,
            "message": "No valid HTTP or HTTPS destinations available to check.",
            "checked_urls": [],
            "provider": "Google Safe Browsing v4",
            "details": {},
        }

    # 4. Perform Provider Lookup
    res = query_google_safe_browsing(normalized_urls, api_key=key_to_use, timeout=effective_timeout)
    res["checked_urls"] = normalized_urls
    res["provider"] = "Google Safe Browsing v4"
    return res
