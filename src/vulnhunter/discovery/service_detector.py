"""Service identification and banner grabbing engine."""

import asyncio
import httpx
from typing import List, Optional
from vulnhunter.core.models import ServiceInfo

SERVICE_PORT_MAP = {
    21: ("ftp", "ftp"),
    22: ("ssh", "ssh"),
    25: ("smtp", "smtp"),
    53: ("dns", "dns"),
    80: ("http", "http"),
    110: ("pop3", "pop3"),
    143: ("imap", "imap"),
    443: ("https", "https"),
    445: ("smb", "microsoft-ds"),
    1433: ("mssql", "ms-sql-s"),
    1521: ("oracle", "oracle"),
    3306: ("mysql", "mysql"),
    3389: ("ms-wbt-server", "rdp"),
    5432: ("postgresql", "postgresql"),
    6379: ("redis", "redis"),
    8000: ("http-alt", "http"),
    8080: ("http-proxy", "http"),
    8443: ("https-alt", "https"),
    9200: ("elasticsearch", "http"),
    27017: ("mongodb", "mongodb"),
}

async def grab_tcp_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempts raw TCP banner grab."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        # Send a generic probe if banner isn't immediately sent
        writer.write(b"\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
        writer.close()
        await writer.wait_closed()
        if data:
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return None

async def identify_service(host: str, port: int, scheme: str = "http", user_agent: str = "VulnHunter") -> ServiceInfo:
    """Identifies the service running on an open port."""
    default_name, default_proto = SERVICE_PORT_MAP.get(port, (f"unknown-{port}", "tcp"))
    banner = await grab_tcp_banner(host, port)
    
    vendor = None
    product = None
    version = None
    extra = {}

    # HTTP/HTTPS Inspection for web ports or unassigned ports
    if port in (80, 443, 8000, 8080, 8443, 9999) or default_proto in ("http", "https") or default_name.startswith("unknown"):
        url = f"{scheme}://{host}:{port}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": user_agent})
                server_hdr = resp.headers.get("Server", "")
                powered_by = resp.headers.get("X-Powered-By", "")
                
                extra["server_header"] = server_hdr
                extra["x_powered_by"] = powered_by
                extra["http_status"] = resp.status_code

                if server_hdr:
                    banner = f"Server: {server_hdr}"
                    # Common HTTP Server fingerprint parsing e.g. Apache/2.4.49 (Unix)
                    if "apache" in server_hdr.lower():
                        vendor = "apache"
                        product = "http_server"
                        if "/" in server_hdr:
                            version = server_hdr.split("apache/")[1].split(" ")[0]
                    elif "nginx" in server_hdr.lower():
                        vendor = "f5"
                        product = "nginx"
                        if "/" in server_hdr:
                            version = server_hdr.split("nginx/")[1].split(" ")[0]
        except Exception:
            pass

    # Banner parsing for SSH / FTP / MySQL
    if banner:
        banner_lower = banner.lower()
        if "openssh" in banner_lower:
            vendor = "openbsd"
            product = "openssh"
            # e.g., SSH-2.0-OpenSSH_8.2p1
            parts = banner.split("OpenSSH_")
            if len(parts) > 1:
                version = parts[1].split(" ")[0]
        elif "vsftpd" in banner_lower:
            vendor = "vsftpd"
            product = "vsftpd"
            if "vsftpd " in banner_lower:
                version = banner_lower.split("vsftpd ")[1].split(")")[0]

    return ServiceInfo(
        port=port,
        protocol=default_proto,
        service_name=default_name,
        product=product,
        vendor=vendor,
        version=version,
        banner=banner,
        extra_info=extra,
    )
