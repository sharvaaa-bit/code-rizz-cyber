import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SeverityEngine:
    """
    Converts the prototype risk score and evidence
    into a structured incident severity.
    """

    def __init__(self):
        self.thresholds = {
            "LOW": 30,
            "MEDIUM": 60,
            "HIGH": 80,
            "CRITICAL": 100
        }

    def classify(self, risk_result):
        """
        Determine severity from the calculated risk score.
        """

        if not risk_result:
            return {
                "severity": "LOW",
                "risk_score": 0,
                "reason": "No risk assessment available"
            }

        risk_score = risk_result.get(
            "risk_score",
            0
        )

        risk_level = risk_result.get(
            "risk_level",
            "LOW"
        )

        # ---------------------------------------------------------
        # Severity classification
        # ---------------------------------------------------------

        if risk_score >= 81:
            severity = "CRITICAL"

        elif risk_score >= 61:
            severity = "HIGH"

        elif risk_score >= 31:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        # ---------------------------------------------------------
        # Explain the decision
        # ---------------------------------------------------------

        reason = self._build_reason(
            severity,
            risk_score,
            risk_level
        )

        result = {
            "severity": severity,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "reason": reason,

            "assessed_at":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "assessment_type":
                "rule_based_prototype"
        }

        logger.info(
            "Severity assessed | score=%s | severity=%s",
            risk_score,
            severity
        )

        return result

    @staticmethod
    def _build_reason(
        severity,
        risk_score,
        risk_level
    ):
        if severity == "CRITICAL":
            return (
                f"Risk score {risk_score} indicates a "
                "critical-level correlated security condition "
                "requiring immediate investigation."
            )

        if severity == "HIGH":
            return (
                f"Risk score {risk_score} indicates a "
                "high-risk security condition requiring "
                "priority investigation."
            )

        if severity == "MEDIUM":
            return (
                f"Risk score {risk_score} indicates a "
                "medium-risk condition requiring "
                "investigation and monitoring."
            )

        return (
            f"Risk score {risk_score} indicates a "
            "low-risk condition suitable for continued "
            "monitoring."
        )


# -------------------------------------------------------------
# Shared severity engine
# -------------------------------------------------------------

severity_engine = SeverityEngine()


def assess_severity(risk_result):
    """
    Public interface used by the security pipeline.
    """

    return severity_engine.classify(
        risk_result
    )