"""Unit tests for Vulnerability Correlation engine."""

from vulnhunter.core.models import ServiceInfo, FindingStatus
from vulnhunter.correlation.cve_correlator import correlate_services_and_tech

def test_correlate_vulnerable_service(test_db):
    service = ServiceInfo(
        port=80,
        protocol="tcp",
        service_name="http",
        product="http_server",
        vendor="apache",
        version="2.4.49",
        banner="Server: Apache/2.4.49 (Unix)"
    )

    findings = correlate_services_and_tech("127.0.0.1", [service], [], test_db)
    assert len(findings) > 0
    cve_41773 = next((f for f in findings if f.cve_id == "CVE-2021-41773"), None)
    assert cve_41773 is not None
    assert cve_41773.status == FindingStatus.PROBABLE
    assert cve_41773.confidence_score >= 0.80
    assert "2.4.49" in cve_41773.reasoning.why_detected
