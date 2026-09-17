"""Asynchronous TCP port discovery scanner."""

import asyncio
import socket
from typing import List, Tuple

async def scan_single_port(host: str, port: int, timeout: float = 2.0) -> Tuple[int, bool]:
    """Test TCP connection to host:port."""
    conn = asyncio.open_connection(host, port)
    try:
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, OSError):
        return port, False

async def discover_open_ports(host: str, ports: List[int], timeout: float = 2.0, max_concurrent: int = 50) -> List[int]:
    """Scans a list of ports asynchronously and returns list of open ports."""
    open_ports: List[int] = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def bounded_scan(port: int):
        async with semaphore:
            p, is_open = await scan_single_port(host, port, timeout=timeout)
            if is_open:
                open_ports.append(p)

    tasks = [bounded_scan(p) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(open_ports)
