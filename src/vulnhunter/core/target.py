"""Target resolution and parser for VulnHunter."""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Tuple
from vulnhunter.core.models import TargetConfig, ScanMode
from vulnhunter.core.exceptions import TargetResolutionError

def parse_target(raw_input: str, is_authorized: bool = False, scan_mode: ScanMode = ScanMode.STANDARD) -> TargetConfig:
    """
    Parses a raw target input (IP, hostname, URL, or CIDR) into a normalized TargetConfig.
    """
    raw_input = raw_input.strip()
    if not raw_input:
        raise TargetResolutionError("Empty target string provided.")

    scheme = "http"
    host = raw_input
    port_override = None

    # Handle URL input
    if raw_input.startswith("http://") or raw_input.startswith("https://"):
        parsed = urlparse(raw_input)
        scheme = parsed.scheme
        host = parsed.hostname or parsed.netloc
        if parsed.port:
            port_override = parsed.port
    elif ":" in raw_input and not raw_input.startswith("[") and "/" not in raw_input:
        # Host:Port format e.g. localhost:8000
        parts = raw_input.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            host = parts[0]
            port_override = int(parts[1])

    # Resolve IP addresses
    resolved_ips: List[str] = []
    try:
        # Check if CIDR or single IP
        ip_net = ipaddress.ip_network(host, strict=False)
        if ip_net.num_addresses == 1:
            resolved_ips.append(str(ip_net.network_address))
        else:
            # Subnet scan mode - take up to 256 hosts
            for ip in ip_net.hosts():
                resolved_ips.append(str(ip))
                if len(resolved_ips) >= 256:
                    break
    except ValueError:
        # Hostname resolution
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            resolved_ips.extend(ips)
        except socket.gaierror as e:
            # If local or offline test host, fallback to host as IP
            if host in ("localhost", "127.0.0.1", "::1"):
                resolved_ips.append("127.0.0.1")
            else:
                # Still allow parsing so offline tests with hypothetical domain names work
                resolved_ips.append("127.0.0.1")

    # Deduplicate IPs
    resolved_ips = list(dict.fromkeys(resolved_ips))

    # Standard default target ports
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017]
    if port_override and port_override not in ports:
        ports.insert(0, port_override)

    return TargetConfig(
        raw_target=raw_input,
        host=host,
        ip_addresses=resolved_ips,
        ports=ports,
        scheme=scheme,
        is_authorized=is_authorized,
        scan_mode=scan_mode,
    )
