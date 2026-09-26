"""
Hybrid risk aggregation engine.

Combines rule-based scores (deterministic, explainable) with
ML anomaly scores (statistical, pattern-based) into a single
risk assessment per session.

Formula: combined = 0.7 × rule_score + 0.3 × (ml_anomaly × 100)
"""

from __future__ import annotations

from app.models.enums import RiskLevel
from app.models.schemas import SessionInfo


def aggregate_risk(rule_score: int, ml_anomaly_score: float) -> tuple[int, RiskLevel, float]:
    """
    Compute hybrid risk score.

    Args:
        rule_score: Penalty from rule engine (0-100, higher = riskier).
        ml_anomaly_score: Anomaly score from ML (0.0-1.0, higher = more unusual).

    Returns:
        (combined_score, risk_level, confidence) where:
        - combined_score is in [0, 100]
        - risk_level is the severity classification
        - confidence is a 0-100 measure of how confident the assessment is
    """
    combined = int(0.7 * rule_score + 0.3 * (ml_anomaly_score * 100))
    combined = max(0, min(combined, 100))

    # Confidence increases when rules and ML agree
    rule_severity = rule_score / 100.0
    agreement = 1.0 - abs(rule_severity - ml_anomaly_score)
    confidence = round(agreement * 100, 1)

    if combined >= 75:
        risk_level = RiskLevel.CRITICAL
    elif combined >= 50:
        risk_level = RiskLevel.HIGH
    elif combined >= 25:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return combined, risk_level, confidence


def compute_security_posture(sessions: list[SessionInfo]) -> int:
    """
    Compute overall security posture for a capture.

    Returns a score from 0-100 where 100 is perfect security.
    This is the inverse of the average risk score.
    """
    if not sessions:
        return 100

    avg_risk = sum(s.rule_score for s in sessions) / len(sessions)
    return max(0, 100 - int(avg_risk))
