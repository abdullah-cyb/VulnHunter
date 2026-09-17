"""OSV API integration module for VulnHunter."""

import httpx
from typing import List, Optional
from vulnhunter.core.config import OSV_V1_API_URL
from vulnhunter.core.models import CVEItem, SeverityLevel
from vulnhunter.core.logger import logger

async def query_osv_vulnerabilities(package_name: str, version: str, ecosystem: Optional[str] = None) -> List[CVEItem]:
    """
    Queries the OSV.dev API for vulnerabilities affecting a specific package and version.
    """
    results: List[CVEItem] = []
    payload = {
        "package": {"name": package_name},
        "version": version
    }
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(OSV_V1_API_URL, json=payload)
            if resp.status_code != 200:
                return results

            data = resp.json()
            vulns = data.get("vulns", [])
            
            for item in vulns:
                vuln_id = item.get("id")
                aliases = item.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                summary = item.get("summary") or item.get("details", "No description provided.")
                
                results.append(CVEItem(
                    cve_id=cve_id,
                    description=summary,
                    cvss_v3_score=7.5,
                    severity=SeverityLevel.HIGH,
                    cisa_kev=False,
                    references=[ref.get("url") for ref in item.get("references", []) if ref.get("url")],
                ))
    except Exception as e:
        logger.debug(f"OSV query error for {package_name} {version}: {e}")

    return results
