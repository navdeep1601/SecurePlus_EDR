"""
SecurePulse EDR - Web Dashboard (Flask)
Real-time alert viewer with JSON API endpoints.
"""

import json
import os
import sys

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, request

ALERT_LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "alerts.json")

app = Flask(__name__, template_folder="templates")


def _load_alerts():
    try:
        with open(ALERT_LOG, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


# ─── Routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = _load_alerts()
    severity = request.args.get("severity")
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity.upper()]
    return jsonify(alerts)


@app.route("/api/summary")
def api_summary():
    alerts  = _load_alerts()
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": len(alerts)}
    for a in alerts:
        sev = a.get("severity", "INFO").upper()
        if sev in summary:
            summary[sev] += 1
    return jsonify(summary)


@app.route("/api/alerts/<alert_id>")
def api_alert_detail(alert_id):
    alerts = _load_alerts()
    for a in alerts:
        if a.get("alert_id") == alert_id:
            return jsonify(a)
    return jsonify({"error": "Alert not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
