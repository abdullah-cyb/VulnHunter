"""Asynchronous Web Crawler module for VulnHunter."""

import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Set, List, Tuple

async def crawl_target(start_url: str, max_depth: int = 2, max_pages: int = 25, user_agent: str = "VulnHunter") -> Tuple[List[str], List[str]]:
    """
    Crawls web application starting from start_url.
    Returns (discovered_urls, discovered_form_endpoints).
    """
    parsed_start = urlparse(start_url)
    target_netloc = parsed_start.netloc

    visited: Set[str] = set()
    to_visit: List[Tuple[str, int]] = [(start_url, 0)]
    discovered_urls: Set[str] = set([start_url])
    discovered_forms: Set[str] = set()

    async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
        while to_visit and len(visited) < max_pages:
            current_url, depth = to_visit.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                resp = await client.get(current_url, headers={"User-Agent": user_agent})
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Collect links (<a href="...">)
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    full_url = urljoin(current_url, href)
                    parsed_href = urlparse(full_url)
                    
                    if parsed_href.netloc == target_netloc:
                        discovered_urls.add(full_url)
                        if depth < max_depth and full_url not in visited:
                            to_visit.append((full_url, depth + 1))

                # Collect forms (<form action="...">)
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    full_action = urljoin(current_url, action)
                    discovered_forms.add(full_action)

            except Exception:
                pass

    return sorted(list(discovered_urls)), sorted(list(discovered_forms))
