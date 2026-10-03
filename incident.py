import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class IncidentEngine:
    """
    Creates a structured security incident from
    correlated evidence, risk analysis, and severity.
    """

    def create_incident(
        self,
        incident_candidate,
        risk_result,
        severity_result
    ):
        """
        Build the final incident object.
        """

        if not incident_candidate:
            return None

        incident_id = (
            f"INC-{uuid.uuid4().hex[:8].upper()}"
        )

        incident = {
            "incident_id": incident_id,

            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "severity": severity_result.get(
                "severity",
                "LOW"
            ),

            "risk_score": risk_result.get(
                "risk_score",
                0
            ),

            "risk_level": risk_result.get(
                "risk_level",
                "LOW"
            ),

            "confidence": self._calculate_confidence(
                incident_candidate,
                risk_result
            ),

            "status": "INVESTIGATING",

            "assets": incident_candidate.get(
                "assets",
                []
            ),

            "detection_count": incident_candidate.get(
                "detection_count",
                0
            ),

            "correlation_score": incident_candidate.get(
                "correlation_score",
                0
            ),

            "summary": self._build_summary(
                severity_result,
                incident_candidate
            ),

            "evidence": incident_candidate.get(
                "evidence",
                []
            ),

            "risk_factors": risk_result.get(
                "risk_factors",
                []
            ),

            "severity_reason": severity_result.get(
                "reason",
                ""
            ),

            "response": {
                "state": "PENDING",
                "action": "INVESTIGATE"
            }
        }

        logger.warning(
            "Security incident created | "
            "id=%s | severity=%s | risk=%s",
            incident_id,
            incident["severity"],
            incident["risk_score"]
        )

        return incident

    @staticmethod
    def _calculate_confidence(
        incident_candidate,
        risk_result
    ):
        """
        Calculate a simple prototype confidence value.

        This represents confidence in the correlation analysis,
        not certainty that an attack occurred.
        """

        correlation = incident_candidate.get(
            "correlation_score",
            0
        )

        detection_count = incident_candidate.get(
            "detection_count",
            0
        )

        confidence = 0.40

        if correlation >= 60:
            confidence += 0.20

        elif correlation >= 40:
            confidence += 0.10

        if detection_count >= 3:
            confidence += 0.15

        elif detection_count >= 2:
            confidence += 0.10

        if risk_result.get(
            "risk_score",
            0
        ) >= 70:
            confidence += 0.10

        return min(
            round(confidence, 2),
            0.95
        )

    @staticmethod
    def _build_summary(
        severity_result,
        incident_candidate
    ):
        severity = severity_result.get(
            "severity",
            "LOW"
        )

        detection_count = incident_candidate.get(
            "detection_count",
            0
        )

        asset_count = incident_candidate.get(
            "asset_count",
            0
        )

        return (
            f"{severity} security incident candidate "
            f"generated from {detection_count} related "
            f"anomalous detection(s) across "
            f"{asset_count} asset(s)."
        )


# ---------------------------------------------------------
# Shared incident engine
# ---------------------------------------------------------

incident_engine = IncidentEngine()


def create_incident(
    incident_candidate,
    risk_result,
    severity_result
):
    """
    Public interface for the security pipeline.
    """

    return incident_engine.create_incident(
        incident_candidate,
        risk_result,
        severity_result
    )