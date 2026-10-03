import logging

from security_engine.correlation import correlate_detections
from security_engine.risk import calculate_risk
from security_engine.severity import assess_severity
from security_engine.incident import create_incident

logger = logging.getLogger(__name__)


def process_detections(detections):
    """
    Run detected anomalies through the complete
    XDR security-analysis pipeline.

    Flow:
        detections
        -> correlation
        -> risk
        -> severity
        -> incident
    """

    logger.info(
        "Starting security analysis pipeline | detections=%s",
        len(detections)
    )

    # ---------------------------------------------------------
    # 1. Correlation
    # ---------------------------------------------------------

    correlation_result = correlate_detections(
        detections
    )

    if not correlation_result.get(
        "correlated",
        False
    ):
        return {
            "incident_created": False,
            "correlation": correlation_result,
            "risk": None,
            "severity": None,
            "incident": None
        }

    incident_candidate = correlation_result.get(
        "incident_candidate"
    )

    # ---------------------------------------------------------
    # 2. Risk assessment
    # ---------------------------------------------------------

    risk_result = calculate_risk(
        incident_candidate
    )

    # ---------------------------------------------------------
    # 3. Severity assessment
    # ---------------------------------------------------------

    severity_result = assess_severity(
        risk_result
    )

    # ---------------------------------------------------------
    # 4. Incident creation
    # ---------------------------------------------------------

    incident = create_incident(
        incident_candidate,
        risk_result,
        severity_result
    )

    logger.info(
        "Security pipeline completed | incident=%s",
        incident.get("incident_id")
        if incident
        else "NONE"
    )

    return {
        "incident_created": incident is not None,

        "correlation": correlation_result,

        "risk": risk_result,

        "severity": severity_result,

        "incident": incident
    }
