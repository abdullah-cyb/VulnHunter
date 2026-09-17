# ABDULLAH.CYB VULNHUNTER

> **DISCOVER. CORRELATE. VERIFY. REPORT.**  
> Professional Cybersecurity Vulnerability Discovery, Intelligence Correlation, and Verification Engine.

---

## 🔒 Executive Overview

`ABDULLAH.CYB VulnHunter` is an autonomous senior security engineering CLI application designed for penetration testers, security analysts, and red teams. It executes a **15-stage structured investigation pipeline** against network targets, web applications, and subnets. 

Unlike primitive scanners that generate noise or hardcoded CVE assumptions, **VulnHunter** performs multi-factor evidence correlation, semantic version matching, CISA KEV (Known Exploited Vulnerabilities) verification, and safe controlled active probing.

---

## ⚡ Key Features

- **Real Vulnerability Intelligence Engine**: Local SQLite database populated with CISA KEV catalog data, NVD references, and OSV API integrations. Operates seamlessly offline.
- **15-Stage Investigation Pipeline**: Exposes real-time progress across target analysis, DNS, port discovery, service identification, web technology fingerprinting, version correlation, active verification, and report generation.
- **Strict Authorization Guard**: Prevents intrusive active probing against unauthorized targets unless explicitly enabled (`--authorize`).
- **Evidence Confidence Rating**: Findings are classified as `CONFIRMED`, `PROBABLE`, `POTENTIAL`, or `NOT VERIFIED` based on vendor, product, version, and proof-of-concept verification.
- **Executive Reporting**: Generates interactive HTML reports with dark mode visuals and structured JSON exports.

---

## 🚀 Installation

### Linux First (Kali Linux, Parrot OS, Ubuntu, Debian)

```bash
# Clone repository
git clone https://github.com/abdullah-cyb/vulnhunter.git
cd vulnhunter

# Install package globally or in virtualenv
pip install -e .
```

Verify installation:
```bash
vulnhunter --version
```

---

## 📖 Usage Examples

### 1. Non-Intrusive Passive Reconnaissance & CVE Correlation
```bash
vulnhunter --target 192.168.1.50
```

### 2. Full Authorized Assessment (Includes Safe Active Verification)
```bash
vulnhunter --target https://authorized-lab.example:8443 --authorize --mode DEEP -o ./reports
```

### 3. Subnet Attack Surface Discovery
```bash
vulnhunter --target 10.0.0.0/24 --mode STANDARD
```

### 4. Synchronize Vulnerability Intelligence Database
```bash
vulnhunter --sync-intel
```

---

## 🔬 15-Stage Investigation Pipeline

| Stage # | Stage Name | Purpose |
|:---|:---|:---|
| `[01]` | Target Analysis | Target validation, IP resolution, and authorization verification |
| `[02]` | DNS Resolution | A, AAAA, MX, PTR, and TXT record resolution |
| `[03]` | Attack Surface Discovery | Host reachability & protocol verification |
| `[04]` | Port Discovery | Asynchronous TCP port scanning |
| `[05]` | Service Identification | Banner grabbing & service header parsing |
| `[06]` | Technology Fingerprinting | Deep web framework, CMS, & language fingerprinting |
| `[07]` | Version Analysis | Semantic version extraction & CPE mapping |
| `[08]` | CVE Intelligence | Local SQLite database cross-correlation against CISA KEV |
| `[09]` | Web Crawling | Asynchronous web route and link crawling |
| `[10]` | Endpoint Discovery | Form action and parameter vector discovery |
| `[11]` | Passive Security Analysis | Security headers, CORS, and TLS configuration audit |
| `[12]` | Controlled Active Tests | Safe active probes (SQLi heuristics, XSS, LFI) [Authorized Only] |
| `[13]` | Evidence Validation | Multi-vector confidence calculation (`CONFIRMED`, `PROBABLE`, etc.) |
| `[14]` | Risk Analysis | Aggregated CVSS weighting & CISA KEV prioritization |
| `[15]` | Report Generation | JSON & HTML report rendering |

---

## 🛡️ Safety & Ethics

Active vulnerability verification (`Stage 12`) is strictly gated behind the `--authorize` flag. **VulnHunter** never performs destructive exploitation, denial-of-service, or weaponized payload delivery.

---

## 🧪 Testing Suite

Run full automated unit and integration tests:
```bash
pytest -v
```

---

## 📜 License & Compliance

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
