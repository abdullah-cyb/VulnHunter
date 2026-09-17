"""Endpoint and query parameter discovery module."""

from urllib.parse import urlparse, parse_qs
from typing import List, Set, Tuple


COMMON_PARAM_NAMES = [
    "id",
    "user",
    "username",
    "page",
    "file",
    "doc",
    "folder",
    "path",
    "search",
    "q",
    "query",
    "cat",
    "category",
    "redirect",
    "url",
    "next",
    "action",
    "cmd",
    "exec",
    "dir",
    "lang",
    "view",
    "ref",
]


def extract_endpoints_and_params(
    discovered_urls: List[str],
) -> Tuple[List[str], List[str]]:
    """
    Parse discovered URLs to extract endpoint paths
    and query parameter names.

    Args:
        discovered_urls: A list of discovered URLs.

    Returns:
        A tuple containing:
            - sorted list of endpoint paths
            - sorted list of query parameter names
    """

    endpoints: Set[str] = set()
    params: Set[str] = set()

    for url in discovered_urls:
        parsed = urlparse(url)

        # Extract endpoint path
        path = parsed.path or "/"
        endpoints.add(path)

        # Extract query parameters
        query_dict = parse_qs(parsed.query)

        for parameter_name in query_dict.keys():
            params.add(parameter_name)

    # If no parameters were discovered,
    # use common security-audit parameter names.
    if not params:
        params.update(
            [
                "id",
                "page",
                "file",
                "search",
            ]
        )

    return sorted(endpoints), sorted(params)
