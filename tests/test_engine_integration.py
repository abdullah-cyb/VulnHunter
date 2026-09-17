"""Integration tests for VulnHunter end-to-end scanning engine."""

import pytest
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from pathlib import Path

from vulnhunter.core.target import parse_target
from vulnhunter.core.models import ScanMode
from vulnhunter.core.engine import VulnHunterEngine

class VulnerableHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Simulate Apache 2.4.49 header
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        # Reflected XSS mock endpoint
        if "q=" in self.path:
            query_val = self.path.split("q=")[1]
            html = f"<html><body>Search Results for: {query_val}</body></html>"
            self.wfile.write(html.encode("utf-8"))
        else:
            self.wfile.write(b"<html><body><h1>Vulnerable Test Server</h1><a href='/?q=test'>Search</a></body></html>")

    def log_message(self, format, *args):
        pass  # Suppress HTTP server stdout logs during test execution

@pytest.fixture
def mock_vulnerable_server():
    server = HTTPServer(("127.0.0.1", 9999), VulnerableHTTPHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield "http://127.0.0.1:9999"
    server.shutdown()
    server.server_close()

@pytest.mark.asyncio
async def test_full_vulnhunter_scan_engine(mock_vulnerable_server, tmp_path: Path):
    target_config = parse_target(mock_vulnerable_server, is_authorized=True, scan_mode=ScanMode.STANDARD)
    engine = VulnHunterEngine(target_config)
    
    report = await engine.execute_scan(output_dir=tmp_path)
    
    assert report.total_findings > 0
    cve_found = any(f.cve_id == "CVE-2021-41773" for f in report.findings)
    assert cve_found is True
    
    json_report_file = list(tmp_path.glob("*.json"))[0]
    html_report_file = list(tmp_path.glob("*.html"))[0]
    
    assert json_report_file.exists()
    assert html_report_file.exists()
