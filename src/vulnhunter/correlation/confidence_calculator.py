"""Vulnerability Correlation and Confidence Calculation Engine."""

from vulnhunter.core.models import FindingStatus, CorrelationMetrics, SeverityLevel
from typing import Tuple

def calculate_finding_confidence(metrics: CorrelationMetrics, active_verified: bool = False) -> Tuple[FindingStatus, float]:
    """
    Computes overall finding confidence score (0.0 to 1.0) and FindingStatus based on metrics.
    """
    score = 0.0

    if metrics.vendor_match:
        score += 0.20
    if metrics.product_match:
        score += 0.25
    if metrics.version_match:
        score += 0.30
    if metrics.exposure_detected:
        score += 0.15
    if metrics.kev_status:
        score += 0.10

    # Boost score by evidence confidence
    score = min(1.0, score + (metrics.evidence_confidence * 0.10))

    if active_verified:
        return FindingStatus.CONFIRMED, 1.0

    if metrics.vendor_match and metrics.product_match and metrics.version_match:
        return FindingStatus.PROBABLE, min(0.95, max(0.80, score))
    elif metrics.product_match and (metrics.vendor_match or metrics.exposure_detected):
        return FindingStatus.POTENTIAL, min(0.79, max(0.50, score))
    else:
        return FindingStatus.NOT_VERIFIED, min(0.49, score)
