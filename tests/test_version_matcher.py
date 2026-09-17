"""Unit tests for semantic version matching logic."""

from vulnhunter.correlation.version_matcher import is_version_vulnerable

def test_exact_version_match():
    assert is_version_vulnerable("2.4.49", "==2.4.49") is True
    assert is_version_vulnerable("2.4.50", "==2.4.49") is False

def test_range_version_match():
    assert is_version_vulnerable("2.14.0", ">=2.0,<=2.14.1") is True
    assert is_version_vulnerable("2.16.0", ">=2.0,<=2.14.1") is False

def test_wildcard_version():
    assert is_version_vulnerable("1.2.3", "*") is True
