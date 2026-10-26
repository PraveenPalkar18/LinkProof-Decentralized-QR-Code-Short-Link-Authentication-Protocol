"""LinkProof About and Protocol Documentation Blueprint."""
from __future__ import annotations

from flask import Blueprint, render_template

about_bp = Blueprint("about", __name__)


@about_bp.route("/about")
def about():
    """Render protocol documentation, threat model, and cryptographic architecture."""
    return render_template("about.html")
