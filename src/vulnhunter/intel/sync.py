"""Intelligence synchronization coordinator for VulnHunter."""

import asyncio
from vulnhunter.intel.db import IntelDatabase
from vulnhunter.intel.cisa_kev import fetch_and_sync_cisa_kev
from vulnhunter.core.logger import logger

async def sync_all_intelligence(db: IntelDatabase) -> dict:
    """Synchronize all online feeds into the local SQLite database."""
    logger.info("Starting vulnerability intelligence database sync...")
    kev_count = await fetch_and_sync_cisa_kev(db)
    
    return {
        "status": "success",
        "cisa_kev_records_synced": kev_count,
        "db_location": str(db.db_path)
    }

def run_sync() -> None:
    """CLI entry point for running intelligence database sync."""
    db = IntelDatabase()
    res = asyncio.run(sync_all_intelligence(db))
    print(f"[+] Intelligence Database Synced successfully! {res['cisa_kev_records_synced']} KEV entries refreshed at {res['db_location']}")
