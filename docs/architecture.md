# ABDULLAH.CYB VulnHunter - System Architecture

## Overview

`VulnHunter` is built around an asynchronous, modular architecture separating target parsing, attack surface discovery, intelligence correlation, controlled active verification, and multi-format reporting.

```
                  +--------------------------+
                  |       CLI Interface      |
                  +------------+-------------+
                               |
                               v
                  +--------------------------+
                  |  Target Parser & Config  |
                  +------------+-------------+
                               |
                               v
                  +--------------------------+
                  | 15-Stage Scan Engine     |
                  +------------+-------------+
                               |
       +-----------------------+-----------------------+
       |                       |                       |
       v                       v                       v
+--------------+       +---------------+       +---------------+
| Discovery    |       | Intelligence  |       | Testing       |
| Engine       |       | Engine (DB)   |       | Engine        |
| - DNS        |       | - CISA KEV    |       | - Passive     |
| - TCP Ports  |       | - Local SQLite|       | - Active      |
| - Banners    |       | - OSV API     |       |   (Authorized)|
| - Fingerprint|       +---------------+       +---------------+
+--------------+               |                       |
       |                       |                       |
       +-----------------------+-----------------------+
                               |
                               v
                  +--------------------------+
                  | Vulnerability            |
                  | Correlation Calculator   |
                  +------------+-------------+
                               |
                               v
                  +--------------------------+
                  | Reporting Subsystem      |
                  | - JSON / HTML / Terminal |
                  +--------------------------+
```

## Key Architectural Principles

1. **Non-Blocking Async Engine**: Asynchronous I/O via `asyncio` and `httpx` ensures fast multi-port and multi-route scanning.
2. **Offline-First Intelligence**: SQLite cache allows scans to execute without active internet connectivity.
3. **Safety Guard Architecture**: Explicit authorization flags prevent unauthorized probing against production assets.
