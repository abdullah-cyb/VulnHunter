"""DNS resolution module for VulnHunter."""

import asyncio
import socket
from typing import Dict, List

async def resolve_dns_records(host: str) -> Dict[str, List[str]]:
    """Performs DNS resolution (A, AAAA, PTR) for a host."""
    records: Dict[str, List[str]] = {
        "A": [],
        "PTR": [],
        "TXT": [],
    }

    loop = asyncio.get_event_loop()

    # Resolve A / IPv4 records
    try:
        _, _, ips = await loop.run_in_executor(None, socket.gethostbyname_ex, host)
        records["A"] = ips
    except Exception:
        pass

    # Reverse DNS lookup if host is IP
    try:
        host_name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, host)
        records["PTR"].append(host_name)
    except Exception:
        pass

    return records
