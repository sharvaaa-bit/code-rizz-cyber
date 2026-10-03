import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Defensive anomaly detection engine.

    This prototype uses transparent behavioral rules rather than
    claiming to perform real zero-day or machine-learning detection.
    """

    def __init__(self):
        self.baseline = {
            "failed_login_threshold": 5,
            "unusual_event_types": {
                "suspicious_process",
                "unusual_network",
                "privilege_change"
            }
        }

    def analyze(self, event):
        """
        Analyze one normalized telemetry event.

        Returns a structured detection result.
        """

        findings = []
        indicators = []
        anomaly_score = 0

        event_type = event.get("event_type", "")
        details = event.get("details", {})

        # ---------------------------------------------------------
        # Rule 1: Repeated authentication failures
        # ---------------------------------------------------------

        failed_attempts = details.get("failed_attempts", 0)

        if isinstance(failed_attempts, int):
            if failed_attempts >= self.baseline["failed_login_threshold"]:
                anomaly_score += 30

                findings.append(
                    "Repeated authentication failures detected"
                )

                indicators.append({
                    "type": "authentication_anomaly",
                    "value": failed_attempts
                })

        # ---------------------------------------------------------
        # Rule 2: Suspicious process activity
        # ---------------------------------------------------------

        if event_type == "suspicious_process":

            anomaly_score += 25

            findings.append(
                "Unusual process activity detected"
            )

            indicators.append({
                "type": "process_anomaly",
                "value": details.get(
                    "process",
                    "unknown"
                )
            })

        # ---------------------------------------------------------
        # Rule 3: Unusual network behavior
        # ---------------------------------------------------------

        if event_type == "unusual_network":

            anomaly_score += 25

            findings.append(
                "Unusual network behavior detected"
            )

            indicators.append({
                "type": "network_anomaly",
                "value": details.get(
                    "destination",
                    "unknown"
                )
            })

        # ---------------------------------------------------------
        # Rule 4: Privilege change
        # ---------------------------------------------------------

        if event_type == "privilege_change":

            anomaly_score += 20

            findings.append(
                "Unexpected privilege change detected"
            )

            indicators.append({
                "type": "privilege_anomaly",
                "value": details.get(
                    "action",
                    "unknown"
                )
            })

        # ---------------------------------------------------------
        # Rule 5: Explicit suspicious indicator
        # ---------------------------------------------------------

        if details.get("suspicious") is True:

            anomaly_score += 20

            findings.append(
                "Telemetry contains a suspicious indicator"
            )

            indicators.append({
                "type": "explicit_indicator",
                "value": True
            })

        # ---------------------------------------------------------
        # Normalize score
        # ---------------------------------------------------------

        anomaly_score = min(anomaly_score, 100)

        is_anomalous = anomaly_score > 0

        if anomaly_score >= 70:
            confidence = 0.90
        elif anomaly_score >= 40:
            confidence = 0.75
        elif anomaly_score > 0:
            confidence = 0.60
        else:
            confidence = 0.10

        result = {
            "detection_id": self._generate_detection_id(),
            "event_id": event.get("event_id"),
            "asset": event.get("asset"),
            "detected_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "is_anomalous": is_anomalous,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
            "findings": findings,
            "indicators": indicators
        }

        logger.info(
            "Detection completed | event=%s | anomalous=%s | score=%s",
            event.get("event_id"),
            is_anomalous,
            anomaly_score
        )

        return result

    @staticmethod
    def _generate_detection_id():
        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%d%H%M%S%f")

        return f"DET-{timestamp}"


# -------------------------------------------------------------
# Shared detector instance
# -------------------------------------------------------------

detector = AnomalyDetector()


def analyze_event(event):
    """
    Public function used by the API/backend.
    """

    return detector.analyze(event)