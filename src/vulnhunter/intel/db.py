"""Local SQLite database manager for Vulnerability Intelligence."""

import json
import sqlite3
from typing import List, Optional, Dict, Any
from pathlib import Path
from vulnhunter.core.config import DEFAULT_DB_PATH
from vulnhunter.core.models import CVEItem, SeverityLevel
from vulnhunter.core.logger import logger

class IntelDatabase:
    """SQLite Database manager for caching CVE, CISA KEV, and CPE data locally."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize database schema and insert default seed vulnerability intelligence."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                severity TEXT,
                cisa_kev INTEGER DEFAULT 0,
                kev_date_added TEXT,
                kev_action TEXT,
                cwe TEXT,
                affected_cpes TEXT,
                affected_versions TEXT,
                references_json TEXT,
                updated_at TEXT
            )
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                vendor TEXT,
                product TEXT,
                version_spec TEXT,
                vulnerable INTEGER DEFAULT 1,
                FOREIGN KEY (cve_id) REFERENCES cve_records (cve_id)
            )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vendor_prod ON cpe_matches(vendor, product)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve_records(cisa_kev)")
            conn.commit()

        # Populate seed data if database is empty
        self._seed_initial_intelligence()

    def _seed_initial_intelligence(self) -> None:
        """Seed the local database with real, authoritative CVE and CISA KEV entries."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_records")
            if cursor.fetchone()[0] > 0:
                return  # Already seeded or synced

            logger.info("Populating initial vulnerability intelligence database...")
            
            real_cve_seeds = [
                {
                    "cve_id": "CVE-2021-41773",
                    "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map files outside the document root.",
                    "cvss_v3_score": 7.5,
                    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "severity": "HIGH",
                    "cisa_kev": 1,
                    "kev_date_added": "2021-11-03",
                    "kev_action": "Apply updates per vendor instructions.",
                    "cwe": "CWE-22",
                    "affected_cpes": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
                    "affected_versions": ["2.4.49"],
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773", "https://httpd.apache.org/security/vulnerabilities_24.html"],
                    "vendor": "apache",
                    "product": "http_server",
                    "version_spec": "==2.4.49"
                },
                {
                    "cve_id": "CVE-2021-42013",
                    "description": "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was incomplete. An attacker could use a path traversal attack to map files outside the document root and execute arbitrary code.",
                    "cvss_v3_score": 9.8,
                    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                    "cisa_kev": 1,
                    "kev_date_added": "2021-11-03",
                    "kev_action": "Apply updates per vendor instructions.",
                    "cwe": "CWE-22",
                    "affected_cpes": ["cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"],
                    "affected_versions": ["2.4.50"],
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
                    "vendor": "apache",
                    "product": "http_server",
                    "version_spec": "==2.4.50"
                },
                {
                    "cve_id": "CVE-2021-44228",
                    "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    "cvss_v3_score": 10.0,
                    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                    "cisa_kev": 1,
                    "kev_date_added": "2021-12-10",
                    "kev_action": "Apply updates per vendor instructions or mitigate per CISA guidance.",
                    "cwe": "CWE-502",
                    "affected_cpes": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
                    "affected_versions": ">=2.0-beta9,<=2.14.1",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                    "vendor": "apache",
                    "product": "log4j",
                    "version_spec": ">=2.0,<=2.14.1"
                },
                {
                    "cve_id": "CVE-2014-0160",
                    "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive process memory (Heartbleed).",
                    "cvss_v3_score": 7.5,
                    "cvss_v3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "severity": "HIGH",
                    "cisa_kev": 1,
                    "kev_date_added": "2022-05-25",
                    "kev_action": "Apply updates per vendor instructions.",
                    "cwe": "CWE-126",
                    "affected_cpes": ["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
                    "affected_versions": ">=1.0.1,<=1.0.1f",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "https://heartbleed.com"],
                    "vendor": "openssl",
                    "product": "openssl",
                    "version_spec": ">=1.0.1,<=1.0.1f"
                },
                {
                    "cve_id": "CVE-2021-23017",
                    "description": "A 1-byte memory overwrite vulnerability in Nginx resolver allows a remote attacker to cause a denial of service or potentially execute arbitrary code.",
                    "cvss_v3_score": 7.7,
                    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                    "severity": "HIGH",
                    "cisa_kev": 0,
                    "kev_date_added": None,
                    "kev_action": None,
                    "cwe": "CWE-193",
                    "affected_cpes": ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"],
                    "affected_versions": ">=0.6.18,<=1.20.0",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
                    "vendor": "f5",
                    "product": "nginx",
                    "version_spec": ">=0.6.18,<=1.20.0"
                },
                {
                    "cve_id": "CVE-2017-5638",
                    "description": "Apache Struts 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 Jakarta Multipart parser Remote Code Execution vulnerability via Content-Type header.",
                    "cvss_v3_score": 10.0,
                    "cvss_v3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                    "cisa_kev": 1,
                    "kev_date_added": "2021-11-03",
                    "kev_action": "Apply updates per vendor instructions.",
                    "cwe": "CWE-20",
                    "affected_cpes": ["cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*"],
                    "affected_versions": ">=2.3.0,<=2.3.31",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
                    "vendor": "apache",
                    "product": "struts",
                    "version_spec": ">=2.3.0,<=2.3.31"
                },
                {
                    "cve_id": "CVE-2018-13379",
                    "description": "Fortinet FortiOS 5.6.3 to 5.6.7 and 6.0.0 to 6.0.4 system portal allows unauthenticated remote attacker to download system files via special HTTP requests.",
                    "cvss_v3_score": 9.8,
                    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                    "cisa_kev": 1,
                    "kev_date_added": "2021-11-03",
                    "kev_action": "Apply updates per vendor instructions.",
                    "cwe": "CWE-22",
                    "affected_cpes": ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"],
                    "affected_versions": ">=5.6.3,<=6.0.4",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"],
                    "vendor": "fortinet",
                    "product": "fortios",
                    "version_spec": ">=5.6.3,<=6.0.4"
                },
                {
                    "cve_id": "CVE-2022-22965",
                    "description": "Spring Framework RCE (Spring4Shell) via Data Binder vulnerability allowing unauthenticated attacker to execute arbitrary code on Tomcat servers.",
                    "cvss_v3_score": 9.8,
                    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                    "cisa_kev": 1,
                    "kev_date_added": "2022-04-04",
                    "kev_action": "Apply updates per vendor instructions.",
                    "cwe": "CWE-94",
                    "affected_cpes": ["cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*"],
                    "affected_versions": ">=5.3.0,<=5.3.17",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
                    "vendor": "vmware",
                    "product": "spring_framework",
                    "version_spec": ">=5.3.0,<=5.3.17"
                }
            ]

            for seed in real_cve_seeds:
                aff_vers = seed["affected_versions"] if isinstance(seed["affected_versions"], list) else [seed["affected_versions"]]
                cursor.execute("""
                INSERT OR REPLACE INTO cve_records 
                (cve_id, description, cvss_v3_score, cvss_v3_vector, severity, cisa_kev, kev_date_added, kev_action, cwe, affected_cpes, affected_versions, references_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (
                    seed["cve_id"], seed["description"], seed["cvss_v3_score"],
                    seed["cvss_v3_vector"], seed["severity"], seed["cisa_kev"],
                    seed["kev_date_added"], seed["kev_action"], seed["cwe"],
                    json.dumps(seed["affected_cpes"]), json.dumps(aff_vers),
                    json.dumps(seed["references"])
                ))

                cursor.execute("""
                INSERT INTO cpe_matches (cve_id, vendor, product, version_spec, vulnerable)
                VALUES (?, ?, ?, ?, 1)
                """, (seed["cve_id"], seed["vendor"], seed["product"], seed["version_spec"]))

            conn.commit()

    def query_cves_by_product(self, vendor: str, product: str) -> List[CVEItem]:
        """Query CVE items matching vendor and product from local intelligence DB."""
        results: List[CVEItem] = []
        vendor_clean = vendor.lower().strip()
        product_clean = product.lower().strip()

        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
            SELECT r.* FROM cve_records r
            JOIN cpe_matches m ON r.cve_id = m.cve_id
            WHERE LOWER(m.vendor) = ? OR LOWER(m.product) = ?
            """
            cursor.execute(query, (vendor_clean, product_clean))
            rows = cursor.fetchall()
            
            for row in rows:
                cpes = json.loads(row["affected_cpes"]) if row["affected_cpes"] else []
                versions_raw = json.loads(row["affected_versions"]) if row["affected_versions"] else []
                versions = versions_raw if isinstance(versions_raw, list) else [versions_raw]
                refs = json.loads(row["references_json"]) if row["references_json"] else []

                severity_enum = SeverityLevel.MEDIUM
                try:
                    severity_enum = SeverityLevel(row["severity"])
                except Exception:
                    pass

                results.append(CVEItem(
                    cve_id=row["cve_id"],
                    description=row["description"],
                    cvss_v3_score=row["cvss_v3_score"],
                    cvss_v3_vector=row["cvss_v3_vector"],
                    severity=severity_enum,
                    cisa_kev=bool(row["cisa_kev"]),
                    kev_date_added=row["kev_date_added"],
                    kev_action=row["kev_action"],
                    affected_cpes=cpes,
                    affected_versions=versions,
                    references=refs,
                    cwe=row["cwe"],
                ))

        return results

    def upsert_cve(self, cve_item: CVEItem, vendor: str, product: str, version_spec: str) -> None:
        """Upsert CVE record into database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO cve_records 
            (cve_id, description, cvss_v3_score, cvss_v3_vector, severity, cisa_kev, kev_date_added, kev_action, cwe, affected_cpes, affected_versions, references_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """, (
                cve_item.cve_id, cve_item.description, cve_item.cvss_v3_score,
                cve_item.cvss_v3_vector, cve_item.severity.value, 1 if cve_item.cisa_kev else 0,
                cve_item.kev_date_added, cve_item.kev_action, cve_item.cwe,
                json.dumps(cve_item.affected_cpes), json.dumps(cve_item.affected_versions),
                json.dumps(cve_item.references)
            ))

            cursor.execute("""
            INSERT INTO cpe_matches (cve_id, vendor, product, version_spec, vulnerable)
            VALUES (?, ?, ?, ?, 1)
            """, (cve_item.cve_id, vendor, product, version_spec))

            conn.commit()
