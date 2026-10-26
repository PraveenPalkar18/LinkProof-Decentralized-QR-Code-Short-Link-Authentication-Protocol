"""LinkProof Dashboard Blueprint."""
from __future__ import annotations

from flask import Blueprint, render_template
from models.database import get_verification_stats, list_recent_verifications

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Render the main security dashboard with stats and recent verifications."""
    stats = get_verification_stats()
    recent = list_recent_verifications(limit=15)
    return render_template("dashboard.html", stats=stats, recent=recent)
