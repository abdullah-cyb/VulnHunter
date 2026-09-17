"""Controlled Active Verification Engine for VulnHunter."""

import uuid
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from vulnhunter.core.models import TargetConfig, Finding, FindingStatus, SeverityLevel, CorrelationMetrics, FindingReasoning, ExploitInfo
from vulnhunter.core.logger import logger
from vulnhunter.core.exceptions import AuthorizationRequiredError

SQLI_PAYLOADS = ["'", "''", "1' OR '1'='1"]
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "psycopg2.errors",
    "sqlite3.operationalerror",
    "ora-00933: sql command not properly ended",
    "warning: mysql_",
]

XSS_PAYLOAD = "<vulnhunter_xss_probe_1337>"
LFI_PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]

async def execute_active_tests(target_config: TargetConfig, endpoints: List[str], params: List[str]) -> List[Finding]:
    """
    Executes controlled, safe active vulnerability tests against endpoints & parameters.
    REQUIRES target_config.is_authorized == True.
    """
    if not target_config.is_authorized:
        logger.info("Active testing skipped: Target is not authorized for intrusive probing.")
        return []

    findings: List[Finding] = []
    base_url = f"{target_config.scheme}://{target_config.host}"
    if target_config.ports and target_config.ports[0] not in (80, 443):
        base_url += f":{target_config.ports[0]}"

    async with httpx.AsyncClient(verify=False, timeout=1.5, follow_redirects=False) as client:
        # Test each param across discovered endpoints
        for endpoint in (endpoints[:5] or ["/"]):
            url = f"{base_url}{endpoint}"
            
            for param in (params[:5] or ["id"]):
                # 1. SQL Injection Heuristic Probing
                for payload in SQLI_PAYLOADS:
                    test_url = f"{url}?{param}={payload}"
                    try:
                        resp = await client.get(test_url, headers={"User-Agent": target_config.user_agent})
                        body_lower = resp.text.lower()

                        for err in SQL_ERROR_PATTERNS:
                            if err in body_lower:
                                metrics = CorrelationMetrics(
                                    vendor_match=True,
                                    product_match=True,
                                    exposure_detected=True,
                                    cve_severity=SeverityLevel.HIGH,
                                    evidence_confidence=1.0,
                                )
                                findings.append(Finding(
                                    id=str(uuid.uuid4())[:8],
                                    cve_id=None,
                                    title=f"Potential SQL Injection Heuristic Discovered in parameter '{param}'",
                                    category="Controlled Active Verification",
                                    severity=SeverityLevel.HIGH,
                                    status=FindingStatus.CONFIRMED,
                                    confidence_score=1.0,
                                    target=target_config.raw_target,
                                    endpoint=endpoint,
                                    vector=f"GET Parameter '{param}'",
                                    metrics=metrics,
                                    reasoning=FindingReasoning(
                                        what_is_it=f"SQL Database syntax error reflected in application response when submitting single-quote payload.",
                                        why_detected=f"Submitting payload '{payload}' to parameter '{param}' triggered database error signature: '{err}'.",
                                        evidence_supporting=f"Request URL: {test_url}\nTriggered Database Error String: '{err}' in HTTP response body.",
                                        confidence_explanation="CONFIRMED (1.00): Database syntax exception directly observed in HTTP response.",
                                        impact_assessment="Allows unauthenticated remote attacker to extract database contents or execute commands.",
                                        verification_guide=f"Send GET request: {test_url} and inspect response for SQL syntax errors.",
                                        remediation_steps="Use parameterized queries / prepared statements (e.g. PDO, PreparedStatement, ORM) for all SQL operations.",
                                        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                                    ),
                                    exploit_info=ExploitInfo(
                                        mechanism="SQL Injection vulnerability via unsanitized SQL string concatenation.",
                                        prerequisites="Accessible HTTP endpoint with database query input.",
                                        impact="Unauthorized database disclosure and modification.",
                                        safe_verification_procedure=f"curl -g '{test_url}'",
                                        remediation="Enforce parameterized SQL queries across all database drivers.",
                                        official_references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                                    )
                                ))
                                break
                    except Exception:
                        pass

                # 2. Reflected XSS Sanitization Probing
                test_xss_url = f"{url}?{param}={XSS_PAYLOAD}"
                try:
                    resp = await client.get(test_xss_url, headers={"User-Agent": target_config.user_agent})
                    if XSS_PAYLOAD in resp.text:
                        findings.append(Finding(
                            id=str(uuid.uuid4())[:8],
                            cve_id=None,
                            title=f"Reflected Cross-Site Scripting (XSS) in parameter '{param}'",
                            category="Controlled Active Verification",
                            severity=SeverityLevel.HIGH,
                            status=FindingStatus.CONFIRMED,
                            confidence_score=1.0,
                            target=target_config.raw_target,
                            endpoint=endpoint,
                            vector=f"GET Parameter '{param}'",
                            metrics=CorrelationMetrics(exposure_detected=True, cve_severity=SeverityLevel.HIGH, evidence_confidence=1.0),
                            reasoning=FindingReasoning(
                                what_is_it=f"Unsanitized user input reflected directly into HTTP HTML response body without encoding.",
                                why_detected=f"Submitting payload '{XSS_PAYLOAD}' to parameter '{param}' returned raw unescaped payload in HTTP response.",
                                evidence_supporting=f"Request URL: {test_xss_url}\nUnescaped Payload Present in Response HTML.",
                                confidence_explanation="CONFIRMED (1.00): Payload reflected raw in client HTML DOM.",
                                impact_assessment="Attacker can execute arbitrary JavaScript in victim browser context, stealing session tokens or credentials.",
                                verification_guide=f"Send GET request: {test_xss_url} and inspect response HTML.",
                                remediation_steps="Apply contextual HTML entity encoding (e.g. htmlspecialchars, DOMPurify) to all reflected user inputs.",
                                references=["https://owasp.org/www-community/attacks/xss/"]
                            ),
                            exploit_info=ExploitInfo(
                                mechanism="Reflected XSS via missing HTML output encoding.",
                                prerequisites="Victim opens attacker-crafted link.",
                                impact="Client-side session hijacking.",
                                safe_verification_procedure=f"curl -g '{test_xss_url}'",
                                remediation="Contextually encode output variables in template engine.",
                                official_references=["https://owasp.org/www-community/attacks/xss/"]
                            )
                        ))
                except Exception:
                    pass

                # 3. Path Traversal / LFI Probing
                for lfi_p in LFI_PAYLOADS:
                    test_lfi_url = f"{url}?{param}={lfi_p}"
                    try:
                        resp = await client.get(test_lfi_url, headers={"User-Agent": target_config.user_agent})
                        if "root:x:0:0:" in resp.text or "[extensions]" in resp.text.lower():
                            findings.append(Finding(
                                id=str(uuid.uuid4())[:8],
                                cve_id=None,
                                title=f"Path Traversal / Local File Inclusion (LFI) in parameter '{param}'",
                                category="Controlled Active Verification",
                                severity=SeverityLevel.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                confidence_score=1.0,
                                target=target_config.raw_target,
                                endpoint=endpoint,
                                vector=f"GET Parameter '{param}'",
                                metrics=CorrelationMetrics(exposure_detected=True, cve_severity=SeverityLevel.CRITICAL, evidence_confidence=1.0),
                                reasoning=FindingReasoning(
                                    what_is_it="Arbitrary file read vulnerability due to improper path normalization.",
                                    why_detected=f"Payload '{lfi_p}' returned local system file contents (/etc/passwd or win.ini).",
                                    evidence_supporting=f"Request URL: {test_lfi_url}\nSystem file signature detected in response.",
                                    confidence_explanation="CONFIRMED (1.00): System file contents successfully read.",
                                    impact_assessment="Attacker can read arbitrary system configuration files, credentials, and source code.",
                                    verification_guide=f"Send GET request: {test_lfi_url}",
                                    remediation_steps="Sanitize file path inputs using path.basename() and validate against strict whitelist.",
                                    references=["https://owasp.org/www-community/attacks/Path_Traversal"]
                                ),
                                exploit_info=ExploitInfo(
                                    mechanism="Path Traversal directory escape via relative path characters.",
                                    prerequisites="Direct HTTP access to file download/view endpoint.",
                                    impact="Full system file disclosure.",
                                    safe_verification_procedure=f"curl -g '{test_lfi_url}'",
                                    remediation="Validate user input against allowed filenames whitelist.",
                                    official_references=["https://owasp.org/www-community/attacks/Path_Traversal"]
                                )
                            ))
                            break
                    except Exception:
                        pass

    return findings
