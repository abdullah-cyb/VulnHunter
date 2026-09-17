"""Endpoint and query parameter discovery module."""

from urllib.parse import urlparse, parse_qs
from typing import List, Set, Dict

COMMON_PARAM_NAMES = [
    "id", "user", "username", "page", "file", "doc", "folder", "path",
    "search", "q", "query", "cat", "category", "redirect", "url", "next",
    "action", "cmd", "exec", "dir", "lang", "view", "ref"
]

def extract_endpoints_and_params(discovered_urls: List[str]) -> Tuple[List[str], List[str]]:
    """
    Parses discovered URLs to extract endpoint paths and query parameter names.
    Returns (endpoints, parameter_names).
    """
    endpoints: Set[str] = set()
    params: Set[str] = set()

    for url in discovered_urls:
        parsed = urlparse(url)
        path = parsed.path or "/"
        endpoints.add(path)

        # Parse query params
        query_dict = parse_qs(parsed.query)
        for p in query_dict.keys():
            params.add(p)

    # If no parameters discovered from links, include common security audit parameter heuristics
    if not params:
        params.update(["id", "page", "file", "search"])

    return sorted(list(endpoints)), sorted(list(params))
