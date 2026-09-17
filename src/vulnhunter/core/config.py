"""Configuration settings for VulnHunter."""

import os
from pathlib import Path

# Paths
DEFAULT_HOME_DIR = Path.home() / ".vulnhunter"
DEFAULT_DB_PATH = DEFAULT_HOME_DIR / "vulnhunter.db"
DEFAULT_REPORTS_DIR = DEFAULT_HOME_DIR / "reports"

# Ensure directories exist
DEFAULT_HOME_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Vulnerability Feed URLs
CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_V1_API_URL = "https://api.osv.dev/v1/query"

# Scanner defaults
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_MAX_CONCURRENT_TASKS = 20
DEFAULT_USER_AGENT = "Abdullah.Cyb-VulnHunter/1.0.0 (Authorized Security Assessment Engine)"
