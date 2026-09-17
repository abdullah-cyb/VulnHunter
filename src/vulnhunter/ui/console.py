"""Rich terminal findings renderer for VulnHunter UI."""

import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import List
from vulnhunter.core.models import Finding, ScanReport, FindingStatus, SeverityLevel

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

SEVERITY_STYLES = {
    SeverityLevel.CRITICAL: "bold red",
    SeverityLevel.HIGH: "bold orange3",
    SeverityLevel.MEDIUM: "bold yellow",
    SeverityLevel.LOW: "bold blue",
    SeverityLevel.INFO: "dim white",
}

STATUS_STYLES = {
    FindingStatus.CONFIRMED: "bold green",
    FindingStatus.PROBABLE: "bold yellow",
    FindingStatus.POTENTIAL: "bold cyan",
    FindingStatus.NOT_VERIFIED: "dim white",
}

def display_findings_summary(report: ScanReport) -> None:
    """Displays findings summary table in Rich terminal."""
    if not report.findings:
        console.print("\n[bold green][+] Assessment Complete: No security vulnerabilities discovered.[/bold green]\n")
        return

    console.print(f"\n[bold cyan]=== VULNERABILITY FINDINGS SUMMARY ({len(report.findings)} Total) ===[/bold cyan]\n")

    table = Table(border_style="cyan", expand=True)
    table.add_column("ID", style="bold dim white", width=10)
    table.add_column("CVE / Title", style="bold white")
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Status", justify="center", width=14)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Endpoint", style="cyan", width=18)

    for f in report.findings:
        sev_style = SEVERITY_STYLES.get(f.severity, "white")
        stat_style = STATUS_STYLES.get(f.status, "white")

        table.add_row(
            f.id,
            f.title,
            Text(f.severity.value, style=sev_style),
            Text(f.status.value, style=stat_style),
            f"{f.confidence_score*100:.0f}%",
            f.endpoint,
        )

    console.print(table)

def display_detailed_finding(f: Finding) -> None:
    """Prints single detailed finding panel with human-like investigation breakdown."""
    sev_style = SEVERITY_STYLES.get(f.severity, "white")
    stat_style = STATUS_STYLES.get(f.status, "white")

    content = Text()
    content.append(f"FINDING: {f.title}\n", style="bold white")
    content.append(f"SEVERITY: {f.severity.value}  |  STATUS: {f.status.value} ({f.confidence_score*100:.0f}% Confidence)\n", style=f"{sev_style}")
    content.append("-" * 70 + "\n\n", style="dim white")

    content.append("1. WHAT IS IT?\n", style="bold cyan")
    content.append(f"{f.reasoning.what_is_it}\n\n", style="white")

    content.append("2. WHY WAS IT DETECTED?\n", style="bold cyan")
    content.append(f"{f.reasoning.why_detected}\n\n", style="white")

    content.append("3. WHAT EVIDENCE SUPPORTS IT?\n", style="bold cyan")
    content.append(f"{f.reasoning.evidence_supporting}\n\n", style="yellow")

    content.append("4. CONFIDENCE ANALYSIS\n", style="bold cyan")
    content.append(f"{f.reasoning.confidence_explanation}\n\n", style="white")

    content.append("5. IMPACT ASSESSMENT\n", style="bold cyan")
    content.append(f"{f.reasoning.impact_assessment}\n\n", style="white")

    content.append("6. AUTHORIZED VERIFICATION PROCEDURE\n", style="bold cyan")
    content.append(f"{f.reasoning.verification_guide}\n\n", style="green")

    content.append("7. REMEDIATION GUIDANCE\n", style="bold cyan")
    content.append(f"{f.reasoning.remediation_steps}\n", style="white")

    panel = Panel(content, title=f"[{sev_style}]Finding Details [{f.id}][/{sev_style}]", border_style="cyan", padding=(1, 2))
    console.print(panel)
