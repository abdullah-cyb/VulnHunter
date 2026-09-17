"""Web Technology Fingerprinting Engine."""

import re
import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from vulnhunter.core.models import TechFingerprint

TECH_SIGNATURES = [
    {
        "name": "Apache HTTP Server",
        "vendor": "apache",
        "product": "http_server",
        "category": "Web Server",
        "header_regex": { "server": r"Apache/?([0-9\.]+)?" },
    },
    {
        "name": "Nginx",
        "vendor": "f5",
        "product": "nginx",
        "category": "Web Server",
        "header_regex": { "server": r"nginx/?([0-9\.]+)?" },
    },
    {
        "name": "PHP",
        "vendor": "php",
        "product": "php",
        "category": "Programming Language",
        "header_regex": { "x-powered-by": r"PHP/?([0-9\.]+)?" },
    },
    {
        "name": "Express.js",
        "vendor": "expressjs",
        "product": "express",
        "category": "Web Framework",
        "header_regex": { "x-powered-by": r"Express" },
    },
    {
        "name": "Django",
        "vendor": "djangoproject",
        "product": "django",
        "category": "Web Framework",
        "cookie_regex": r"csrftoken",
    },
    {
        "name": "Laravel",
        "vendor": "laravel",
        "product": "laravel",
        "category": "Web Framework",
        "cookie_regex": r"laravel_session",
    },
    {
        "name": "WordPress",
        "vendor": "wordpress",
        "product": "wordpress",
        "category": "CMS",
        "html_regex": r"wp-content|wp-includes",
        "meta_generator": r"WordPress ([0-9\.]+)?",
    },
    {
        "name": "Spring Framework",
        "vendor": "vmware",
        "product": "spring_framework",
        "category": "Application Framework",
        "html_regex": r"Whitelabel Error Page",
    },
    {
        "name": "Log4j",
        "vendor": "apache",
        "product": "log4j",
        "category": "Logging Library",
        "header_regex": { "x-log4j": r".*" },
    }
]

async def fingerprint_technologies(target_url: str, user_agent: str = "VulnHunter") -> List[TechFingerprint]:
    """Analyzes target HTTP response to discover technologies, frameworks, and versions."""
    technologies: List[TechFingerprint] = []

    try:
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers={"User-Agent": user_agent})
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html_body = resp.text
            soup = BeautifulSoup(html_body, "html.parser")
            cookies = [k for k in resp.cookies.keys()]
            cookie_str = "; ".join(cookies)

            for sig in TECH_SIGNATURES:
                version = None
                matched = False
                evidence_bits = []

                # Header check
                if "header_regex" in sig:
                    for h_name, h_pattern in sig["header_regex"].items():
                        if h_name in headers:
                            val = headers[h_name]
                            match = re.search(h_pattern, val, re.IGNORECASE)
                            if match:
                                matched = True
                                evidence_bits.append(f"Header '{h_name}: {val}'")
                                if match.groups() and match.group(1):
                                    version = match.group(1)

                # Cookie check
                if "cookie_regex" in sig:
                    if re.search(sig["cookie_regex"], cookie_str, re.IGNORECASE):
                        matched = True
                        evidence_bits.append(f"Cookie pattern matched '{sig['cookie_regex']}'")

                # Meta generator check
                if "meta_generator" in sig:
                    gen_tag = soup.find("meta", attrs={"name": "generator"})
                    if gen_tag and gen_tag.get("content"):
                        content = gen_tag["content"]
                        match = re.search(sig["meta_generator"], content, re.IGNORECASE)
                        if match:
                            matched = True
                            evidence_bits.append(f"Meta Generator: '{content}'")
                            if match.groups() and match.group(1):
                                version = match.group(1)

                # HTML regex check
                if "html_regex" in sig:
                    if re.search(sig["html_regex"], html_body, re.IGNORECASE):
                        matched = True
                        evidence_bits.append(f"HTML pattern matched '{sig['html_regex']}'")

                if matched:
                    technologies.append(TechFingerprint(
                        name=sig["name"],
                        vendor=sig.get("vendor"),
                        version=version,
                        category=sig["category"],
                        confidence=1.0 if version else 0.8,
                        evidence=", ".join(evidence_bits),
                        cpe=f"cpe:2.3:a:{sig.get('vendor')}:{sig.get('product')}:{version or '*'}:*:*:*:*:*:*:*"
                    ))

    except Exception as e:
        pass

    return technologies
