import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Transparent risk-scoring engine for the XDR prototype.

    The score is a project-specific analytical value.
    It is NOT an industry-standard security score.
    """

    def __init__(self):
        self.max_score = 100

    def calculate(self, incident_candidate):
        """
        Calculate a risk score from correlated evidence.
        """

        if not incident_candidate:
            return {
                "risk_score": 0,
                "risk_factors": [],
                "risk_level": "LOW"
            }

        risk_score = 0
        risk_factors = []

        # ---------------------------------------------------------
        # 1. Correlation strength
        # ---------------------------------------------------------

        correlation_score = incident_candidate.get(
            "correlation_score",
            0
        )

        correlation_contribution = round(
            correlation_score * 0.30
        )

        risk_score += correlation_contribution

        if correlation_score >= 70:
            risk_factors.append({
                "factor": "strong_correlation",
                "contribution": correlation_contribution
            })

        # ---------------------------------------------------------
        # 2. Number of anomalous detections
        # ---------------------------------------------------------

        detection_count = incident_candidate.get(
            "detection_count",
            0
        )

        detection_contribution = min(
            detection_count * 10,
            30
        )

        risk_score += detection_contribution

        if detection_count >= 2:
            risk_factors.append({
                "factor": "multiple_anomalous_events",
                "contribution": detection_contribution
            })

        # ---------------------------------------------------------
        # 3. Number of affected assets
        # ---------------------------------------------------------

        asset_count = incident_candidate.get(
            "asset_count",
            0
        )

        asset_contribution = min(
            asset_count * 10,
            20
        )

        risk_score += asset_contribution

        if asset_count >= 2:
            risk_factors.append({
                "factor": "multiple_assets",
                "contribution": asset_contribution
            })

        # ---------------------------------------------------------
        # 4. Strong anomaly evidence
        # ---------------------------------------------------------

        total_anomaly_score = incident_candidate.get(
            "total_anomaly_score",
            0
        )

        evidence_contribution = min(
            round(total_anomaly_score * 0.20),
            20
        )

        risk_score += evidence_contribution

        if total_anomaly_score >= 70:
            risk_factors.append({
                "factor": "strong_anomaly_evidence",
                "contribution": evidence_contribution
            })

        # ---------------------------------------------------------
        # Keep score within 0-100
        # ---------------------------------------------------------

        risk_score = min(
            round(risk_score),
            self.max_score
        )

        # ---------------------------------------------------------
        # Prototype risk bands
        # ---------------------------------------------------------

        if risk_score >= 81:
            risk_level = "CRITICAL"

        elif risk_score >= 61:
            risk_level = "HIGH"

        elif risk_score >= 31:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        result = {
            "risk_score": risk_score,

            "risk_level": risk_level,

            "calculated_at":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "risk_factors": risk_factors,

            "method": {
                "type": "transparent_rule_based",
                "maximum_score": self.max_score
            }
        }

        logger.info(
            "Risk calculated | score=%s | level=%s",
            risk_score,
            risk_level
        )

        return result


# -------------------------------------------------------------
# Shared risk engine
# -------------------------------------------------------------

risk_engine = RiskEngine()


def calculate_risk(incident_candidate):
    """
    Public interface used by the security pipeline.
    """

    return risk_engine.calculate(
        incident_candidate
    )