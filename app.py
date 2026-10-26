"""LinkProof Application Factory and Entry Point.

A Decentralized QR Code and Short-Link Authentication Protocol
Using ECDSA and Multi-Hop TLS Verification.
"""
from __future__ import annotations

import os
from typing import Optional
from flask import Flask, jsonify, render_template, request

from config import Config, TestConfig
from core.security import get_csrf_token
from models.database import init_db
from routes.about import about_bp
from routes.api import api_bp
from routes.dashboard import dashboard_bp
from routes.keys import keys_bp
from routes.publisher import publisher_bp
from routes.verifier import verifier_bp


def create_app(test_config: Optional[type] = None) -> Flask:
    """Create and configure the LinkProof Flask application."""
    app = Flask(__name__)

    if test_config:
        app.config.from_object(test_config)
    else:
        app.config.from_object(Config)

    # Initialize SQLite database
    db_path = app.config.get("DATABASE_PATH")
    init_db(db_path)

    # Register Jinja context helpers
    @app.context_processor
    def inject_helpers():
        return {
            "csrf_token": get_csrf_token(),
            "protocol_version": Config.PROTOCOL_VERSION,
        }

    # Add security response headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy allowing self and inline styles/scripts for modern UI
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:;"
        )
        return response

    # Safe error handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Access Forbidden / CSRF Mismatch"}), 403
        return render_template("error.html", code=403, title="Forbidden", message=str(error.description)), 403

    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Resource Not Found"}), 404
        return render_template("error.html", code=404, title="Page Not Found", message="The requested URL does not exist on this server."), 404

    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Internal Server Error"}), 500
        return render_template("error.html", code=500, title="Server Error", message="An unexpected internal error occurred. No sensitive details are disclosed."), 500

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(publisher_bp)
    app.register_blueprint(verifier_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(about_bp)
    app.register_blueprint(api_bp)

    return app


app = create_app()

if __name__ == "__main__":
    # Academic/Local development binding to 127.0.0.1 (never 0.0.0.0)
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting LinkProof Security Server on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
