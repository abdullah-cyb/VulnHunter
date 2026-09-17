"""CISA KEV Catalog synchronization engine."""

import httpx
from typing import Dict, Any, List
from vulnhunter.core.config import CISA_KEV_FEED_URL
from vulnhunter.core.models import CVEItem, SeverityLevel
from vulnhunter.core.logger import logger
from vulnhunter.intel.db import IntelDatabase

async def fetch_and_sync_cisa_kev(db: IntelDatabase) -> int:
    """
    Downloads and parses the latest CISA KEV JSON feed, caching results in local database.
    Returns count of updated records.
    """
    logger.info(f"Syncing CISA KEV catalog from {CISA_KEV_FEED_URL}...")
    count = 0
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(CISA_KEV_FEED_URL)
            if resp.status_code != 200:
                logger.warning(f"Failed to fetch CISA KEV feed: HTTP {resp.status_code}")
                return 0
            
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            for item in vulnerabilities:
                cve_id = item.get("cveID")
                vendor = item.get("vendorProject", "").lower()
                product = item.get("product", "").lower()
                description = item.get("shortDescription", "")
                date_added = item.get("dateAdded")
                action = item.get("requiredAction")
                notes = item.get("notes", "")

                cve_item = CVEItem(
                    cve_id=cve_id,
                    description=description,
                    cvss_v3_score=9.0,  # KEV items are actively exploited
                    severity=SeverityLevel.CRITICAL if "Remote Code Execution" in description or "RCE" in description else SeverityLevel.HIGH,
                    cisa_kev=True,
                    kev_date_added=date_added,
                    kev_action=action,
                    references=[notes] if notes else [],
                )
                db.upsert_cve(cve_item, vendor=vendor, product=product, version_spec="*")
                count += 1

            logger.info(f"CISA KEV synchronization completed: {count} vulnerabilities updated.")
            return count
    except Exception as e:
        logger.warning(f"CISA KEV sync failed (operating with cached DB): {e}")
        return 0
