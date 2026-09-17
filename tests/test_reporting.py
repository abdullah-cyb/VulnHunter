"""Unit tests for JSON and HTML reporting."""

from pathlib import Path
from vulnhunter.core.models import ScanReport, ScanMode
from vulnhunter.reporting.json_reporter import export_json_report
from vulnhunter.reporting.html_reporter import export_html_report

def test_export_reports(tmp_path: Path):
    report = ScanReport(
        scan_id="test1234",
        target="127.0.0.1",
        start_time="2026-09-09T12:00:00",
        end_time="2026-09-09T12:00:05",
        duration_seconds=5.0,
        scan_mode=ScanMode.STANDARD,
        authorized=True,
    )

    json_out = tmp_path / "report.json"
    html_out = tmp_path / "report.html"

    export_json_report(report, json_out)
    export_html_report(report, html_out)

    assert json_out.exists()
    assert html_out.exists()
    assert "127.0.0.1" in json_out.read_text(encoding="utf-8")
    assert "VULNHUNTER" in html_out.read_text(encoding="utf-8")
