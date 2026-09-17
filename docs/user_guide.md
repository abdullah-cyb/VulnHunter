# ABDULLAH.CYB VulnHunter - User Guide

## CLI Command Flags

```
usage: vulnhunter [-h] [-t TARGET] [-a] [-m {PASSIVE,STANDARD,DEEP}] [-o OUTPUT] [--sync-intel] [-v] [--version]
```

### Key Arguments
- `-t, --target`: Specifies target host (`127.0.0.1`, `http://localhost:8000`, `192.168.1.0/24`, `authorized-domain.local`).
- `-a, --authorize`: Explicitly authorizes active verification tests.
- `-m, --mode`: Scan mode intensity (`PASSIVE`, `STANDARD`, `DEEP`).
- `-o, --output`: Directory where `.html` and `.json` reports are exported.
- `--sync-intel`: Synchronizes local SQLite CVE database with CISA KEV catalog.

## Sample Execution Workflow

```bash
# Update vulnerability database
vulnhunter --sync-intel

# Perform authorized scan
vulnhunter --target http://127.0.0.1:8000 --authorize -o ./scan_results
```
