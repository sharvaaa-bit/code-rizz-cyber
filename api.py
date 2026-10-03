from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import uuid
import logging
import json

from backend.detector import analyze_event
from security_engine.pipeline import process_detections

from backend.database import (
    initialize_database,
    save_detection,
    save_incident,
    get_connection
)


api = Blueprint("api", __name__)

logger = logging.getLogger(__name__)

detection_store = []
incident_store = []

initialize_database()


def generate_event_id():
    return f"EVT-{uuid.uuid4().hex[:8].upper()}"


def validate_event(event):
    required_fields = [
        "timestamp",
        "source",
        "asset",
        "event_type"
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in event
    ]

    if missing_fields:
        return False, {
            "error": "Invalid telemetry event",
            "missing_fields": missing_fields
        }

    if not isinstance(event.get("details", {}), dict):
        return False, {
            "error": "The 'details' field must be an object"
        }

    return True, None


@api.route("/api/events", methods=["POST"])
def receive_event():

    event = request.get_json(silent=True)

    if not event:
        return jsonify({
            "success": False,
            "error": "Request body must contain JSON"
        }), 400

    valid, error = validate_event(event)

    if not valid:
        return jsonify({
            "success": False,
            **error
        }), 400

    event["event_id"] = event.get(
        "event_id",
        generate_event_id()
    )

    event["ingested_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    event["status"] = "RECEIVED"

    logger.info(
        "Telemetry received | event_id=%s | asset=%s | type=%s",
        event["event_id"],
        event["asset"],
        event["event_type"]
    )

    detection = analyze_event(event)

    detection_store.append(detection)

    save_detection(detection)

    pipeline_result = process_detections(
        detection_store
    )

    incident = pipeline_result.get("incident")

    if incident:

        correlation_id = (
            incident.get("correlation_id")
            or pipeline_result.get(
                "correlation",
                {}
            ).get(
                "incident_candidate",
                {}
            ).get(
                "correlation_id"
            )
        )

        duplicate = False

        for existing_incident in incident_store:

            if (
                correlation_id
                and existing_incident.get(
                    "correlation_id"
                ) == correlation_id
            ):
                duplicate = True
                break

        if not duplicate:

            if correlation_id:
                incident["correlation_id"] = correlation_id

            incident_store.append(incident)

            save_incident(incident)

    return jsonify({
        "success": True,
        "message": "Telemetry processed",
        "event": event,
        "detection": detection,
        "security_analysis": pipeline_result
    }), 202


@api.route("/api/events/test", methods=["POST"])
def test_event():

    test_event_data = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "source": "authorized_simulator",

        "asset": "LAB-ENDPOINT-01",

        "event_type": "authentication",

        "details": {
            "action": "login",
            "result": "success",
            "failed_attempts": 0
        }
    }

    test_event_data["event_id"] = generate_event_id()

    test_event_data["ingested_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    test_event_data["status"] = "RECEIVED"

    detection = analyze_event(
        test_event_data
    )

    detection_store.append(detection)

    save_detection(detection)

    pipeline_result = process_detections(
        detection_store
    )

    incident = pipeline_result.get("incident")

    if incident:

        correlation_id = (
            incident.get("correlation_id")
            or pipeline_result.get(
                "correlation",
                {}
            ).get(
                "incident_candidate",
                {}
            ).get(
                "correlation_id"
            )
        )

        duplicate = False

        for existing_incident in incident_store:

            if (
                correlation_id
                and existing_incident.get(
                    "correlation_id"
                ) == correlation_id
            ):
                duplicate = True
                break

        if not duplicate:

            if correlation_id:
                incident["correlation_id"] = correlation_id

            incident_store.append(incident)

            save_incident(incident)

    return jsonify({
        "success": True,
        "message": "Authorized test telemetry processed",
        "event": test_event_data,
        "detection": detection,
        "security_analysis": pipeline_result
    }), 202


@api.route("/api/detections", methods=["GET"])
def get_detections():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM detections
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    detections = []

    for row in rows:

        detections.append({
            "detection_id": row["detection_id"],
            "event_id": row["event_id"],
            "asset": row["asset"],
            "detected_at": row["detected_at"],
            "is_anomalous": bool(
                row["is_anomalous"]
            ),
            "anomaly_score": row["anomaly_score"],
            "confidence": row["confidence"],
            "findings": json.loads(
                row["findings"] or "[]"
            ),
            "indicators": json.loads(
                row["indicators"] or "[]"
            )
        })

    return jsonify({
        "count": len(detections),
        "detections": detections
    }), 200


@api.route("/api/incidents", methods=["GET"])
def get_incidents():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    incidents = []

    for row in rows:

        incidents.append({
            "incident_id": row["incident_id"],
            "correlation_id": row["correlation_id"],
            "created_at": row["created_at"],
            "severity": row["severity"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "confidence": row["confidence"],
            "status": row["status"],
            "assets": json.loads(
                row["assets"] or "[]"
            ),
            "detection_count": row["detection_count"],
            "correlation_score": row["correlation_score"],
            "summary": row["summary"],
            "evidence": json.loads(
                row["evidence"] or "[]"
            ),
            "risk_factors": json.loads(
                row["risk_factors"] or "[]"
            ),
            "severity_reason": row["severity_reason"],
            "response": json.loads(
                row["response"] or "{}"
            )
        })

    return jsonify({
        "count": len(incidents),
        "incidents": incidents
    }), 200


@api.route("/api/events/schema", methods=["GET"])
def event_schema():

    return jsonify({
        "event_schema": {
            "event_id": "string",
            "timestamp": "ISO-8601 timestamp",
            "source": "string",
            "asset": "string",
            "event_type": "string",
            "details": "object",
            "ingested_at": "ISO-8601 timestamp",
            "status": "string"
        }
    }), 200