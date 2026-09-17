"""Pytest test fixtures for VulnHunter."""

import pytest
import tempfile
import gc
from pathlib import Path
from vulnhunter.intel.db import IntelDatabase
from vulnhunter.core.models import TargetConfig, ScanMode

@pytest.fixture
def temp_db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = Path(f.name)
    yield path
    gc.collect()
    try:
        if path.exists():
            path.unlink()
    except PermissionError:
        pass

@pytest.fixture
def test_db(temp_db_path):
    db = IntelDatabase(db_path=temp_db_path)
    yield db
    del db
    gc.collect()

@pytest.fixture
def sample_target_config():
    return TargetConfig(
        raw_target="http://127.0.0.1:8000",
        host="127.0.0.1",
        ip_addresses=["127.0.0.1"],
        ports=[8000],
        scheme="http",
        is_authorized=True,
        scan_mode=ScanMode.STANDARD,
    )
