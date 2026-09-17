# Changelog

All notable changes to **ABDULLAH.CYB VulnHunter** will be documented in this file.

## [1.0.0] - 2026-09-09

### Added
- **15-Stage Autonomous Scan Engine**: Structured multi-phase attack surface discovery and verification pipeline.
- **Vulnerability Intelligence Subsystem**: Local SQLite database with CISA KEV catalog sync, seed intelligence, and OSV API integration.
- **Evidence Confidence Rating**: Status metrics (`CONFIRMED`, `PROBABLE`, `POTENTIAL`, `NOT VERIFIED`).
- **Controlled Active Verification**: Safe SQLi, XSS, and LFI heuristic probes gated by explicit authorization (`--authorize`).
- **Rich Terminal UI**: Professional cybersecurity interface layout with real-time stage progress monitoring.
- **Reporting Engine**: Standalone HTML report generator with dark mode layout and JSON exporter.
- **Comprehensive Test Suite**: Automated unit and end-to-end integration tests using pytest.
