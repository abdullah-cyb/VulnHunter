# Vulnerability Intelligence Subsystem

## Database Schema

The vulnerability database uses SQLite stored locally at `~/.vulnhunter/vulnhunter.db`.

### `cve_records` Table
- `cve_id` (TEXT PRIMARY KEY)
- `description` (TEXT)
- `cvss_v3_score` (REAL)
- `cvss_v3_vector` (TEXT)
- `severity` (TEXT)
- `cisa_kev` (INTEGER 0/1)
- `kev_date_added` (TEXT)
- `kev_action` (TEXT)
- `affected_cpes` (JSON Array)
- `affected_versions` (JSON Array)
- `references_json` (JSON Array)

## Confidence Calculation Matrix

| Vendor Match | Product Match | Version Match | Exposure | KEV Status | Confidence Score | Status Rating |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Yes | Yes | Yes | Yes | Yes | `0.95+` | `PROBABLE` |
| Yes | Yes | No | Yes | No | `0.50 - 0.79` | `POTENTIAL` |
| Active Proof Verified | - | - | - | - | `1.00` | `CONFIRMED` |
