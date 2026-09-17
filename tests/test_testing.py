"""Unit tests for Passive and Active testing modules."""

import pytest
from vulnhunter.core.models import TargetConfig, ScanMode
from vulnhunter.testing.active_tester import execute_active_tests

@pytest.mark.asyncio
async def test_active_testing_unauthorized_guard():
    config = TargetConfig(
        raw_target="127.0.0.1",
        host="127.0.0.1",
        is_authorized=False,
        scan_mode=ScanMode.STANDARD
    )
    findings = await execute_active_tests(config, ["/"], ["id"])
    assert len(findings) == 0  # Must skip completely when unauthorized
