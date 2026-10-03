import sqlite3
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "xdr.db"


def get_connection():
    DATA_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id TEXT UNIQUE NOT NULL,
            event_id TEXT,
            asset TEXT,
            detected_at TEXT,
            is_anomalous INTEGER,
            anomaly_score INTEGER,
            confidence REAL,
            findings TEXT,
            indicators TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            correlation_id TEXT,
            created_at TEXT,
            severity TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            confidence REAL,
            status TEXT,
            assets TEXT,
            detection_count INTEGER,
            correlation_score INTEGER,
            summary TEXT,
            evidence TEXT,
            risk_factors TEXT,
            severity_reason TEXT,
            response TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_detection(detection):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO detections (
            detection_id,
            event_id,
            asset,
            detected_at,
            is_anomalous,
            anomaly_score,
            confidence,
            findings,
            indicators
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        detection.get("detection_id"),
        detection.get("event_id"),
        detection.get("asset"),
        detection.get("detected_at"),
        int(detection.get("is_anomalous", False)),
        detection.get("anomaly_score", 0),
        detection.get("confidence", 0),
        json.dumps(detection.get("findings", [])),
        json.dumps(detection.get("indicators", []))
    ))

    connection.commit()
    connection.close()


def save_incident(incident):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO incidents (
            incident_id,
            correlation_id,
            created_at,
            severity,
            risk_score,
            risk_level,
            confidence,
            status,
            assets,
            detection_count,
            correlation_score,
            summary,
            evidence,
            risk_factors,
            severity_reason,
            response
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident.get("incident_id"),
        incident.get("correlation_id"),
        incident.get("created_at"),
        incident.get("severity"),
        incident.get("risk_score", 0),
        incident.get("risk_level"),
        incident.get("confidence", 0),
        incident.get("status"),
        json.dumps(incident.get("assets", [])),
        incident.get("detection_count", 0),
        incident.get("correlation_score", 0),
        incident.get("summary"),
        json.dumps(incident.get("evidence", [])),
        json.dumps(incident.get("risk_factors", [])),
        incident.get("severity_reason"),
        json.dumps(incident.get("response", {}))
    ))

    connection.commit()
    connection.close()
    