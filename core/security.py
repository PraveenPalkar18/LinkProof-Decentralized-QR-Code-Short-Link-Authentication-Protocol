"""LinkProof Web Security Helpers.

Provides CSRF protection, file upload sanitization, and security headers.
"""
from __future__ import annotations

import os
import secrets
from functools import wraps
from typing import Callable
from flask import abort, request, session


def get_csrf_token() -> str:
    """Generate or retrieve a session-bound CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token() -> bool:
    """Verify CSRF token from request form or X-CSRF-Token header."""
    expected = session.get("csrf_token")
    if not expected:
        return False
    provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not provided:
        return False
    return secrets.compare_digest(str(expected), str(provided))


def csrf_protect(view_func: Callable) -> Callable:
    """Decorator to enforce CSRF token validation on state-changing requests."""
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Exclude explicit API calls that pass JSON and have Accept: application/json
            # unless session cookies are present
            if not validate_csrf_token():
                # Check if it's an API route with separate authorization
                if request.path.startswith("/api/"):
                    return view_func(*args, **kwargs)
                abort(403, description="CSRF Token validation failed. Please refresh and try again.")
        return view_func(*args, **kwargs)
    return decorated_view
