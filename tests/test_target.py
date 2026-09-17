"""Unit tests for target parsing and resolution."""

import pytest
from vulnhunter.core.target import parse_target
from vulnhunter.core.models import ScanMode

def test_parse_target_ip():
    config = parse_target("127.0.0.1")
    assert config.host == "127.0.0.1"
    assert config.ip_addresses == ["127.0.0.1"]
    assert config.scheme == "http"

def test_parse_target_url():
    config = parse_target("https://authorized-lab.example:8443/app", is_authorized=True)
    assert config.host == "authorized-lab.example"
    assert config.scheme == "https"
    assert 8443 in config.ports
    assert config.is_authorized is True

def test_parse_target_host_port():
    config = parse_target("localhost:8000")
    assert config.host == "localhost"
    assert 8000 in config.ports
