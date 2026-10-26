"""LinkProof SQLite Database Module.

Manages persistent stores for trusted issuer keys, local publisher keys,
and tamper-evident verification audit history.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import Config


_MEMORY_CONN: Optional[sqlite3.Connection] = None

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create and return a configured SQLite connection."""
    global _MEMORY_CONN
    target_path = db_path or Config.DATABASE_PATH
    if target_path == ":memory:":
        if _MEMORY_CONN is None:
            _MEMORY_CONN = sqlite3.connect("file:linkproof_mem?mode=memory&cache=shared", uri=True)
            _MEMORY_CONN.row_factory = sqlite3.Row
            _MEMORY_CONN.execute("PRAGMA foreign_keys = ON;")
        conn = sqlite3.connect("file:linkproof_mem?mode=memory&cache=shared", uri=True)
    else:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(target_path)

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables and indexes."""
    with get_db_connection(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS trusted_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer_id TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                label TEXT,
                is_trusted INTEGER NOT NULL DEFAULT 1,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS publisher_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer_id TEXT NOT NULL,
                encrypted_private_key_pem TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                label TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT,
                verified_at TEXT NOT NULL,
                issuer_id TEXT,
                issuer_fingerprint TEXT,
                destination_url TEXT NOT NULL,
                final_url TEXT,
                status TEXT NOT NULL,
                signature_valid INTEGER NOT NULL DEFAULT 0,
                issuer_trusted INTEGER NOT NULL DEFAULT 0,
                is_expired INTEGER NOT NULL DEFAULT 0,
                is_replay INTEGER NOT NULL DEFAULT 0,
                destination_matched INTEGER NOT NULL DEFAULT 0,
                tls_valid INTEGER NOT NULL DEFAULT 0,
                hops_count INTEGER NOT NULL DEFAULT 0,
                offline_mode INTEGER NOT NULL DEFAULT 0,
                report_json TEXT,
                client_ip TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_trusted_fp ON trusted_keys(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_history_record_id ON verification_history(record_id);
            CREATE INDEX IF NOT EXISTS idx_history_verified_at ON verification_history(verified_at DESC);
        """)
        conn.commit()


# =========================================================================
# Trusted Keys Management
# =========================================================================

def add_trusted_key(
    issuer_id: str,
    public_key_pem: str,
    fingerprint: str,
    label: Optional[str] = None,
    is_trusted: bool = True,
    notes: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Register or update a trusted issuer public key."""
    clean_fp = fingerprint.replace(":", "").replace(" ", "").upper()
    now_utc = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO trusted_keys (issuer_id, public_key_pem, fingerprint, label, is_trusted, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                issuer_id = excluded.issuer_id,
                public_key_pem = excluded.public_key_pem,
                label = excluded.label,
                is_trusted = excluded.is_trusted,
                notes = excluded.notes
            """,
            (issuer_id.strip(), public_key_pem.strip(), clean_fp, label or "", 1 if is_trusted else 0, notes or "", now_utc),
        )
        conn.commit()
        return cur.lastrowid or 0


def get_trusted_key_by_fingerprint(
    fingerprint: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve trusted key record by its SHA-256 fingerprint."""
    clean_fp = fingerprint.replace(":", "").replace(" ", "").upper()
    with get_db_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM trusted_keys WHERE fingerprint = ?",
            (clean_fp,),
        ).fetchone()
        return dict(row) if row else None


def list_trusted_keys(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all trusted issuer keys sorted by creation date."""
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM trusted_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def toggle_trusted_key_status(key_id: int, is_trusted: bool, db_path: Optional[str] = None) -> bool:
    """Toggle trust status (trusted / untrusted) for a key."""
    with get_db_connection(db_path) as conn:
        cur = conn.execute(
            "UPDATE trusted_keys SET is_trusted = ? WHERE id = ?",
            (1 if is_trusted else 0, key_id),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_trusted_key(key_id: int, db_path: Optional[str] = None) -> bool:
    """Delete a trusted key entry by ID."""
    with get_db_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM trusted_keys WHERE id = ?", (key_id,))
        conn.commit()
        return cur.rowcount > 0


# =========================================================================
# Publisher Key Store
# =========================================================================

def save_publisher_key(
    issuer_id: str,
    encrypted_private_key_pem: str,
    public_key_pem: str,
    fingerprint: str,
    label: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Save an encrypted publisher key pair to the publisher store."""
    clean_fp = fingerprint.replace(":", "").replace(" ", "").upper()
    now_utc = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO publisher_keys (issuer_id, encrypted_private_key_pem, public_key_pem, fingerprint, label, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                issuer_id = excluded.issuer_id,
                encrypted_private_key_pem = excluded.encrypted_private_key_pem,
                public_key_pem = excluded.public_key_pem,
                label = excluded.label
            """,
            (issuer_id.strip(), encrypted_private_key_pem.strip(), public_key_pem.strip(), clean_fp, label or "", now_utc),
        )
        conn.commit()
        return cur.lastrowid or 0


def list_publisher_keys(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all publisher keys (private keys excluded or metadata only)."""
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, issuer_id, public_key_pem, fingerprint, label, created_at FROM publisher_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_publisher_key_by_id(key_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get full publisher key record including encrypted private key."""
    with get_db_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM publisher_keys WHERE id = ?",
            (key_id,),
        ).fetchone()
        return dict(row) if row else None


# =========================================================================
# Verification History & Replay Detection
# =========================================================================

def check_record_replay(record_id: str, db_path: Optional[str] = None) -> Tuple[bool, int, Optional[str]]:
    """Check if record ID has been seen in history.

    Returns (is_duplicate, previous_seen_count, first_verified_at).
    """
    if not record_id:
        return False, 0, None

    with get_db_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) as cnt, MIN(verified_at) as first_seen
            FROM verification_history
            WHERE record_id = ?
            """,
            (record_id,),
        ).fetchone()
        if row and row["cnt"] > 0:
            return True, row["cnt"], row["first_seen"]
        return False, 0, None


def record_verification(
    destination_url: str,
    status: str,
    record_id: Optional[str] = None,
    issuer_id: Optional[str] = None,
    issuer_fingerprint: Optional[str] = None,
    final_url: Optional[str] = None,
    signature_valid: bool = False,
    issuer_trusted: bool = False,
    is_expired: bool = False,
    is_replay: bool = False,
    destination_matched: bool = False,
    tls_valid: bool = False,
    hops_count: int = 0,
    offline_mode: bool = False,
    report_data: Optional[Dict[str, Any]] = None,
    client_ip: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Log an audit entry for a verification attempt."""
    now_utc = datetime.now(timezone.utc).isoformat()
    clean_fp = issuer_fingerprint.replace(":", "").replace(" ", "").upper() if issuer_fingerprint else ""
    report_json_str = json.dumps(report_data or {}, ensure_ascii=False)

    with get_db_connection(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO verification_history (
                record_id, verified_at, issuer_id, issuer_fingerprint,
                destination_url, final_url, status, signature_valid,
                issuer_trusted, is_expired, is_replay, destination_matched,
                tls_valid, hops_count, offline_mode, report_json, client_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                now_utc,
                issuer_id,
                clean_fp,
                destination_url,
                final_url or destination_url,
                status,
                1 if signature_valid else 0,
                1 if issuer_trusted else 0,
                1 if is_expired else 0,
                1 if is_replay else 0,
                1 if destination_matched else 0,
                1 if tls_valid else 0,
                hops_count,
                1 if offline_mode else 0,
                report_json_str,
                client_ip or "127.0.0.1",
            ),
        )
        conn.commit()
        return cur.lastrowid or 0


def get_verification_stats(db_path: Optional[str] = None) -> Dict[str, int]:
    """Calculate aggregate security and verification statistics."""
    with get_db_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM verification_history").fetchone()[0]
        valid_sigs = conn.execute("SELECT COUNT(*) FROM verification_history WHERE signature_valid = 1").fetchone()[0]
        # Only genuinely verified signed records (signature valid AND issuer trusted)
        verified_count = conn.execute(
            "SELECT COUNT(*) FROM verification_history WHERE status = 'VERIFIED' AND signature_valid = 1 AND issuer_trusted = 1"
        ).fetchone()[0]
        invalid_sigs = conn.execute("SELECT COUNT(*) FROM verification_history WHERE status = 'INVALID_SIGNATURE'").fetchone()[0]
        unknown_issuers = conn.execute(
            "SELECT COUNT(*) FROM verification_history WHERE status IN ('UNKNOWN_ISSUER', 'REVOKED_KEY')"
        ).fetchone()[0]
        expired_count = conn.execute("SELECT COUNT(*) FROM verification_history WHERE is_expired = 1").fetchone()[0]
        mismatch_count = conn.execute("SELECT COUNT(*) FROM verification_history WHERE status = 'DESTINATION_MISMATCH'").fetchone()[0]
        tls_failed_count = conn.execute("SELECT COUNT(*) FROM verification_history WHERE status = 'TLS_VALIDATION_FAILED'").fetchone()[0]
        ssrf_blocked_count = conn.execute("SELECT COUNT(*) FROM verification_history WHERE status = 'SSRF_BLOCKED'").fetchone()[0]
        unauthenticated_audits = conn.execute(
            "SELECT COUNT(*) FROM verification_history WHERE status = 'AUDIT_COMPLETE_UNAUTHENTICATED' OR issuer_id = 'UNTRUSTED_RAW_URL'"
        ).fetchone()[0]
        threats_detected = conn.execute("SELECT COUNT(*) FROM verification_history WHERE status = 'THREAT_DETECTED'").fetchone()[0]

        return {
            "total": total,
            "verified": verified_count,
            "valid_signatures": valid_sigs,
            "invalid_signatures": invalid_sigs,
            "unknown_issuers": unknown_issuers,
            "expired": expired_count,
            "destination_mismatches": mismatch_count,
            "tls_failures": tls_failed_count,
            "ssrf_blocked": ssrf_blocked_count,
            "unauthenticated_audits": unauthenticated_audits,
            "threats_detected": threats_detected,
        }


def list_recent_verifications(limit: int = 25, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve recent verification history entries."""
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, record_id, verified_at, issuer_id, issuer_fingerprint,
                   destination_url, final_url, status, signature_valid,
                   issuer_trusted, is_expired, is_replay, destination_matched,
                   tls_valid, hops_count, offline_mode
            FROM verification_history
            ORDER BY verified_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_verification_by_id(history_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve detailed verification record by ID, parsing stored JSON report."""
    with get_db_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM verification_history WHERE id = ?",
            (history_id,),
        ).fetchone()
        if not row:
            return None
        res = dict(row)
        try:
            res["report"] = json.loads(res.get("report_json") or "{}")
        except Exception:
            res["report"] = {}
        return res
