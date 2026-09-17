"""JSON Report Generator for VulnHunter."""

import json
from pathlib import Path
from vulnhunter.core.models import ScanReport

def export_json_report(report: ScanReport, output_path: Path) -> Path:
    """Exports ScanReport object to structured JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))
    return output_path
