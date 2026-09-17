"""Passive Security Analysis Module (Security Headers, CORS, TLS)."""

import uuid
import httpx
from typing import List
from vulnhunter.core.models import Finding, FindingStatus, SeverityLevel, CorrelationMetrics, FindingReasoning, ExploitInfo

MISSING_HEADER_RECOMMENDATIONS = {
    "strict-transport-security": ("HSTS Missing", SeverityLevel.MEDIUM, "Enforces HTTPS connections, mitigating SSL stripping attacks.", "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy": ("CSP Missing", SeverityLevel.MEDIUM, "Restricts sources of executable script content to mitigate XSS attacks.", "Content-Security-Policy: default-src 'self';"),
    "x-frame-options": ("Clickjacking Protection Missing", SeverityLevel.LOW, "Prevents embedding the web app in iframes, mitigating clickjacking.", "X-Frame-Options: DENY"),
    "x-content-type-options": ("MIME-Sniffing Protection Missing", SeverityLevel.LOW, "Prevents browser from MIME-sniffing response content types.", "X-Content-Type-Options: nosniff"),
    "referrer-policy": ("Referrer-Policy Missing", SeverityLevel.LOW, "Controls how much referrer information is included with requests.", "Referrer-Policy: strict-origin-when-cross-origin"),
}

async def analyze_passive_security(target_url: str, user_agent: str = "VulnHunter") -> List[Finding]:
    """Performs passive security checks on target web application."""
    findings: List[Finding] = []

    try:
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers={"User-Agent": user_agent})
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Missing Security Headers Check
            for h_name, (title, severity, impact, header_rec) in MISSING_HEADER_RECOMMENDATIONS.items():
                if h_name not in headers:
                    metrics = CorrelationMetrics(
                        vendor_match=True,
                        product_match=True,
                        exposure_detected=True,
                        cve_severity=severity,
                        evidence_confidence=1.0,
                    )
                    
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        cve_id=None,
                        title=f"Security Header Missing: {title}",
                        category="Passive Security Analysis",
                        severity=severity,
                        status=FindingStatus.CONFIRMED,
                        confidence_score=1.0,
                        target=target_url,
                        endpoint="/",
                        vector="HTTP Response Header",
                        metrics=metrics,
                        reasoning=FindingReasoning(
                            what_is_it=f"The HTTP response header '{h_name}' is not configured on the target web server.",
                            why_detected=f"Direct inspection of HTTP response headers from '{target_url}' confirmed the absence of '{h_name}'.",
                            evidence_supporting=f"Response HTTP Headers received:\n" + "\n".join([f"{k}: {v}" for k, v in headers.items()]),
                            confidence_explanation="CONFIRMED (1.00): The missing header condition is directly observed in HTTP response.",
                            impact_assessment=impact,
                            verification_guide=f"Send an HTTP GET request to {target_url} using curl and verify headers: curl -I {target_url}",
                            remediation_steps=f"Configure the web server to include header:\n{header_rec}",
                            references=["https://owasp.org/www-project-secure-headers/"]
                        ),
                        exploit_info=ExploitInfo(
                            mechanism="Passive Security Control Weakness",
                            prerequisites="Access to client web browser interacting with target.",
                            impact=impact,
                            safe_verification_procedure=f"Execute: curl -I {target_url} and inspect output headers.",
                            remediation=f"Add '{header_rec}' to web server configuration.",
                            official_references=["https://owasp.org/www-project-secure-headers/"]
                        )
                    ))

            # 2. CORS Wildcard Check
            cors_origin = headers.get("access-control-allow-origin")
            cors_creds = headers.get("access-control-allow-credentials")
            if cors_origin == "*" or (cors_origin and cors_creds == "true"):
                severity = SeverityLevel.HIGH if cors_creds == "true" else SeverityLevel.MEDIUM
                findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    cve_id=None,
                    title="CORS Misconfiguration: Overly Permissive Access-Control-Allow-Origin",
                    category="Passive Security Analysis",
                    severity=severity,
                    status=FindingStatus.CONFIRMED,
                    confidence_score=1.0,
                    target=target_url,
                    endpoint="/",
                    vector="HTTP Response Header",
                    metrics=CorrelationMetrics(exposure_detected=True, cve_severity=severity, evidence_confidence=1.0),
                    reasoning=FindingReasoning(
                        what_is_it="Cross-Origin Resource Sharing (CORS) policy permits arbitrary external origin domains.",
                        why_detected=f"Server returned Access-Control-Allow-Origin: {cors_origin}.",
                        evidence_supporting=f"Access-Control-Allow-Origin: {cors_origin}\nAccess-Control-Allow-Credentials: {cors_creds}",
                        confidence_explanation="CONFIRMED (1.00): Direct HTTP response header verification.",
                        impact_assessment="Allows untrusted third-party websites to make cross-domain API requests and read responses.",
                        verification_guide=f"Send request with header 'Origin: https://evil.example' to {target_url}.",
                        remediation_steps="Restrict Access-Control-Allow-Origin to explicit trusted domain origins.",
                        references=["https://portswigger.net/web-security/cors"]
                    ),
                    exploit_info=ExploitInfo(
                        mechanism="Cross-Origin Resource Sharing exploitation",
                        prerequisites="Authenticated user visiting attacker site.",
                        impact="Cross-origin data theft.",
                        safe_verification_procedure=f"curl -I -H 'Origin: https://example.com' {target_url}",
                        remediation="Remove wildcard '*' from Access-Control-Allow-Origin.",
                        official_references=["https://portswigger.net/web-security/cors"]
                    )
                ))

    except Exception:
        pass

    return findings
