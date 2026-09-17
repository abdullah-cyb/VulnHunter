"""CVE Intelligence Correlation Engine."""

import uuid
from typing import List
from vulnhunter.core.models import ServiceInfo, TechFingerprint, Finding, CorrelationMetrics, FindingReasoning, ExploitInfo
from vulnhunter.intel.db import IntelDatabase
from vulnhunter.correlation.version_matcher import is_version_vulnerable
from vulnhunter.correlation.confidence_calculator import calculate_finding_confidence

def correlate_services_and_tech(
    target_str: str,
    services: List[ServiceInfo],
    technologies: List[TechFingerprint],
    db: IntelDatabase
) -> List[Finding]:
    """Correlates discovered services and technologies against local intelligence DB."""
    findings: List[Finding] = []
    seen_cves = set()

    # Process services
    for s in services:
        if not s.product and not s.vendor:
            continue
        
        vendor = s.vendor or s.service_name
        product = s.product or s.service_name
        cves = db.query_cves_by_product(vendor, product)

        for cve in cves:
            if cve.cve_id in seen_cves:
                continue

            # Evaluate version match against affected versions
            version_match = False
            if s.version:
                for spec in cve.affected_versions:
                    if is_version_vulnerable(s.version, spec):
                        version_match = True
                        break
            else:
                # Version unknown
                version_match = False

            metrics = CorrelationMetrics(
                vendor_match=True,
                product_match=True,
                version_match=version_match,
                platform_match=True,
                exposure_detected=True,
                cve_severity=cve.severity,
                kev_status=cve.cisa_kev,
                evidence_confidence=0.9 if s.version else 0.5,
            )

            status, confidence = calculate_finding_confidence(metrics)

            reasoning = FindingReasoning(
                what_is_it=f"{cve.cve_id} - {product.title()} Known Vulnerability",
                why_detected=f"Target service on port {s.port} is running {product} (Version: {s.version or 'Unknown'}). Local CVE database matched {cve.cve_id}.",
                evidence_supporting=f"Service Banner / Port Response: '{s.banner or s.service_name}' on TCP port {s.port}.",
                confidence_explanation=f"Confidence rated {status.value} ({confidence:.2f}) based on Vendor ({vendor}), Product ({product}), and Version correlation ({s.version or 'Unspecified'}).",
                impact_assessment=f"{cve.description} CVSS Score: {cve.cvss_v3_score}. CISA KEV Exploited: {'Yes' if cve.cisa_kev else 'No'}.",
                verification_guide=f"Execute non-intrusive version verification banner query on TCP port {s.port} or check vendor advisory at {cve.references[0] if cve.references else 'NVD'}.",
                remediation_steps=cve.kev_action or f"Upgrade {product} on port {s.port} to the latest patch release.",
                references=cve.references,
            )

            exploit_info = ExploitInfo(
                mechanism="Remote Network Exploitation",
                prerequisites=f"Direct TCP/HTTP access to port {s.port}.",
                impact=cve.description,
                safe_verification_procedure=f"Check service banner on port {s.port} to confirm version patch status.",
                remediation=cve.kev_action or "Apply latest security patches from vendor.",
                official_references=cve.references
            )

            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                cve_id=cve.cve_id,
                title=f"{cve.cve_id}: {product.title()} {cve.severity.value} Vulnerability",
                category="Known CVE Intelligence",
                severity=cve.severity,
                status=status,
                confidence_score=confidence,
                target=target_str,
                endpoint=f"Port {s.port}",
                vector=f"TCP/{s.port}",
                metrics=metrics,
                reasoning=reasoning,
                exploit_info=exploit_info,
            ))
            seen_cves.add(cve.cve_id)

    # Process technologies
    for t in technologies:
        if not t.vendor and not t.name:
            continue

        vendor = t.vendor or t.name.lower()
        product = t.name.lower().replace(" ", "_")
        cves = db.query_cves_by_product(vendor, product)

        for cve in cves:
            if cve.cve_id in seen_cves:
                continue

            version_match = False
            if t.version:
                for spec in cve.affected_versions:
                    if is_version_vulnerable(t.version, spec):
                        version_match = True
                        break

            metrics = CorrelationMetrics(
                vendor_match=True,
                product_match=True,
                version_match=version_match,
                platform_match=True,
                exposure_detected=True,
                cve_severity=cve.severity,
                kev_status=cve.cisa_kev,
                evidence_confidence=t.confidence,
            )

            status, confidence = calculate_finding_confidence(metrics)

            reasoning = FindingReasoning(
                what_is_it=f"{cve.cve_id} - {t.name} Vulnerability",
                why_detected=f"Web Technology Fingerprinting identified {t.name} (Version: {t.version or 'Unknown'}). Intelligence match found in database.",
                evidence_supporting=f"Technology Fingerprint Evidence: '{t.evidence}'.",
                confidence_explanation=f"Confidence rated {status.value} ({confidence:.2f}).",
                impact_assessment=f"{cve.description} CVSS Score: {cve.cvss_v3_score}.",
                verification_guide=f"Inspect application headers or HTTP response artifacts to verify patch level.",
                remediation_steps=cve.kev_action or f"Upgrade {t.name} to non-vulnerable version.",
                references=cve.references,
            )

            exploit_info = ExploitInfo(
                mechanism="HTTP Web Application Vector",
                prerequisites=f"Access to web interface running {t.name}.",
                impact=cve.description,
                safe_verification_procedure="Verify framework version via HTTP response header analysis.",
                remediation="Apply software update.",
                official_references=cve.references
            )

            findings.append(Finding(
                id=str(uuid.uuid4())[:8],
                cve_id=cve.cve_id,
                title=f"{cve.cve_id}: {t.name} {cve.severity.value} Vulnerability",
                category="Web Technology CVE",
                severity=cve.severity,
                status=status,
                confidence_score=confidence,
                target=target_str,
                endpoint="/",
                vector="HTTP/HTTPS",
                metrics=metrics,
                reasoning=reasoning,
                exploit_info=exploit_info,
            ))
            seen_cves.add(cve.cve_id)

    return findings
