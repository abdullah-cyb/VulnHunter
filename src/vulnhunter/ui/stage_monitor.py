"""15-Stage Investigation Progress Monitor for VulnHunter UI."""

import sys
from typing import List
from rich.console import Console
from rich.table import Table
from rich.text import Text
from vulnhunter.core.models import StageInfo, StageStatus

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

STAGES_DEFINITIONS = [
    (1, "Target Analysis"),
    (2, "DNS Resolution"),
    (3, "Attack Surface Discovery"),
    (4, "Port Discovery"),
    (5, "Service Identification"),
    (6, "Technology Fingerprinting"),
    (7, "Version Analysis"),
    (8, "CVE Intelligence"),
    (9, "Web Crawling"),
    (10, "Endpoint Discovery"),
    (11, "Passive Security Analysis"),
    (12, "Controlled Active Tests"),
    (13, "Evidence Validation"),
    (14, "Risk Analysis"),
    (15, "Report Generation"),
]

class StageMonitor:
    """Manages display and execution status of the 15 investigation stages."""

    def __init__(self):
        self.stages: List[StageInfo] = [
            StageInfo(number=num, name=name, status=StageStatus.PENDING)
            for num, name in STAGES_DEFINITIONS
        ]

    def update_stage(self, stage_num: int, status: StageStatus, details: str = "") -> None:
        """Updates status and details for a given stage number."""
        for st in self.stages:
            if st.number == stage_num:
                st.status = status
                st.details = details
                
                # Live status printing to terminal
                status_icon = "[*]"
                style_str = "white"
                if status == StageStatus.RUNNING:
                    status_icon = "[>]"
                    style_str = "bold cyan"
                elif status == StageStatus.COMPLETED:
                    status_icon = "[+]"
                    style_str = "bold green"
                elif status == StageStatus.SKIPPED:
                    status_icon = "[-]"
                    style_str = "dim yellow"
                elif status == StageStatus.FAILED:
                    status_icon = "[x]"
                    style_str = "bold red"

                stage_fmt = f"[{st.number:02d}] {st.name}"
                console.print(f"[{style_str}]{status_icon} {stage_fmt:<32} [dim]{details}[/dim][/{style_str}]")
                break

    def print_stage_summary_table() -> None:
        """Prints a final summary table of all stages."""
        table = Table(title="15-Stage Autonomous Investigation Summary", border_style="cyan")
        table.add_column("Stage #", style="dim cyan", justify="right")
        table.add_column("Stage Name", style="bold white")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="gray50")

        for st in self.stages:
            if st.status == StageStatus.COMPLETED:
                status_text = Text("COMPLETED", style="bold green")
            elif st.status == StageStatus.SKIPPED:
                status_text = Text("SKIPPED", style="dim yellow")
            elif st.status == StageStatus.FAILED:
                status_text = Text("FAILED", style="bold red")
            else:
                status_text = Text("PENDING", style="dim white")

            table.add_row(f"{st.number:02d}", st.name, status_text, st.details)

        console.print(table)
