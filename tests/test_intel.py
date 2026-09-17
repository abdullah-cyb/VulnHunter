"""Unit tests for Vulnerability Intelligence database."""

import pytest
from vulnhunter.core.models import CVEItem, SeverityLevel

def test_intel_db_initialization_and_seed(test_db):
    cves = test_db.query_cves_by_product("apache", "http_server")
    assert len(cves) > 0
    cve_ids = [c.cve_id for c in cves]
    assert "CVE-2021-41773" in cve_ids
    assert "CVE-2021-42013" in cve_ids

def test_cisa_kev_flag_in_intel_db(test_db):
    cves = test_db.query_cves_by_product("apache", "log4j")
    assert len(cves) > 0
    log4j_cve = next((c for c in cves if c.cve_id == "CVE-2021-44228"), None)
    assert log4j_cve is not None
    assert log4j_cve.cisa_kev is True
    assert log4j_cve.severity == SeverityLevel.CRITICAL
