from flask import Flask, jsonify
from datetime import datetime, timezone
import logging

from backend.api import api

app = Flask(__name__)

# --------------------------------------------------
# Configuration
# --------------------------------------------------

app.config["JSON_SORT_KEYS"] = False

app.register_blueprint(api) 

# Basic application logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


# --------------------------------------------------
# Health / System Status
# --------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """
    Basic health check for the XDR backend.
    Used by the frontend and deployment environment
    to verify that the backend is running.
    """

    return jsonify({
        "service": "Adaptive Autonomous XDR",
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat() ,
        "version": "1.0.0"
    }), 200


# --------------------------------------------------
# System Information
# --------------------------------------------------

@app.route("/api/status", methods=["GET"])
def system_status():
    """
    Returns the current high-level state of the
    XDR processing platform.
    """

    return jsonify({
        "platform": "Adaptive Autonomous XDR",
        "environment": "development",
        "telemetry": "ready",
        "detection_engine": "ready",
        "correlation_engine": "ready",
        "risk_engine": "ready",
        "incident_engine": "ready",
        "api": "ready"
    }), 200


# --------------------------------------------------
# Root Endpoint
# --------------------------------------------------

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "name": "Adaptive Autonomous XDR",
        "description": (
            "Defensive security monitoring and incident "
            "analysis platform"
        ),
        "api": "/api",
        "health": "/api/health",
        "status": "/api/status"
    }), 200


# --------------------------------------------------
# Error Handling
# --------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "status": 404
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.exception("Internal server error")

    return jsonify({
        "error": "Internal server error",
        "status": 500
    }), 500


# --------------------------------------------------
# Application Entry Point
# --------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting Adaptive Autonomous XDR backend")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )