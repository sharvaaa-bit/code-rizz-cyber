import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


class CorrelationEngine:
    def __init__(self):
        self.time_window_minutes = 15

    def _parse_timestamp(self, timestamp):
        """Convert an ISO-8601 timestamp into a timezone-aware datetime."""
        if not timestamp:
            return None

        try:
            timestamp = timestamp.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(timestamp)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(timezone.utc)

        except (ValueError, TypeError):
            return None

    def _filter_time_window(self, detections):
        """
        Keep anomalous detections occurring within the configured
        correlation window relative to the newest detection.
        """
        anomalous = [
            detection
            for detection in detections
            if detection.get("is_anomalous") is True
        ]

        if not anomalous:
            return []

        timestamped = []

        for detection in anomalous:
            detected_at = self._parse_timestamp(
                detection.get("detected_at")
            )

            if detected_at:
                timestamped.append((detected_at, detection))

        # If timestamps are unavailable, keep the detections rather
        # than silently throwing away security evidence.
        if not timestamped:
            return anomalous

        newest_time = max(
            timestamp for timestamp, _ in timestamped
        )

        window_start = newest_time - timedelta(
            minutes=self.time_window_minutes
        )

        filtered = [
            detection
            for timestamp, detection in timestamped
            if window_start <= timestamp <= newest_time
        ]

        return filtered

    def correlate(self, detections):
        if not detections:
            return {
                "correlated": False,
                "incident_candidate": None,
                "reason": "No detections supplied"
            }

        # Apply the actual 15-minute correlation window.
        anomalous = self._filter_time_window(detections)

        if not anomalous:
            return {
                "correlated": False,
                "incident_candidate": None,
                "reason": "No anomalous detections found within correlation window"
            }

        assets = {}

        for detection in anomalous:
            asset = detection.get("asset", "UNKNOWN-ASSET")
            assets.setdefault(asset, []).append(detection)

        evidence = []

        for detection in anomalous:
            for finding in detection.get("findings", []):
                evidence.append({
                    "event_id": detection.get("event_id"),
                    "asset": detection.get("asset"),
                    "finding": finding
                })

        detection_count = len(anomalous)
        asset_count = len(assets)

        anomaly_scores = [
            detection.get("anomaly_score", 0)
            for detection in anomalous
        ]

        highest_anomaly = max(anomaly_scores)
        total_anomaly_score = min(
            sum(anomaly_scores),
            100
        )

        correlation_score = 0

        # Multiple related detections.
        if detection_count >= 2:
            correlation_score += 25

        # Stronger evidence when three or more events are related.
        if detection_count >= 3:
            correlation_score += 15

        # Activity spanning multiple assets.
        if asset_count >= 2:
            correlation_score += 20

        # Strength of the strongest anomaly.
        if highest_anomaly >= 70:
            correlation_score += 25
        elif highest_anomaly >= 40:
            correlation_score += 15

        # Combined anomaly evidence.
        if total_anomaly_score >= 80:
            correlation_score += 15

        correlation_score = min(
            correlation_score,
            100
        )

        correlated = (
            detection_count >= 2
            and correlation_score >= 40
        )

        if correlated:
            incident_candidate = {
                "correlation_id": self._generate_correlation_id(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "time_window_minutes": self.time_window_minutes,
                "detection_count": detection_count,
                "asset_count": asset_count,
                "assets": list(assets.keys()),
                "correlation_score": correlation_score,
                "total_anomaly_score": total_anomaly_score,
                "highest_anomaly": highest_anomaly,
                "evidence": evidence,
                "detections": anomalous
            }

            logger.info(
                "Related anomalies correlated | detections=%s | assets=%s | score=%s | window=%smin",
                detection_count,
                asset_count,
                correlation_score,
                self.time_window_minutes
            )

            return {
                "correlated": True,
                "incident_candidate": incident_candidate
            }

        logger.info(
            "Anomalies detected but not sufficiently correlated"
        )

        return {
            "correlated": False,
            "incident_candidate": None,
            "reason": (
                "Anomalous events exist, but the correlation "
                "threshold was not reached"
            ),
            "analysis": {
                "detection_count": detection_count,
                "asset_count": asset_count,
                "highest_anomaly": highest_anomaly,
                "correlation_score": correlation_score,
                "time_window_minutes": self.time_window_minutes
            }
        }

    @staticmethod
    def _generate_correlation_id():
        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%d%H%M%S%f")

        return f"COR-{timestamp}"


correlation_engine = CorrelationEngine()


def correlate_detections(detections):
    return correlation_engine.correlate(detections)