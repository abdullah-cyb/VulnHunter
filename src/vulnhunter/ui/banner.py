"""Branding banner and authorization warning for VulnHunter UI."""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Configure UTF-8 encoding for stdout on Windows environments if needed
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

def print_banner() -> None:
    """Prints executive ABDULLAH.CYB VULNHUNTER brand header."""
    banner_text = Text()
    banner_text.append("ABDULLAH.CYB ", style="bold cyan")
    banner_text.append("VULNHUNTER ", style="bold white")
    banner_text.append("v1.0.0\n", style="bold dim white")
    banner_text.append("DISCOVER. CORRELATE. VERIFY. REPORT.\n", style="bold cyan dim")
    banner_text.append("Autonomous Cybersecurity Vulnerability Discovery & Intelligence Engine", style="italic gray50")

    panel = Panel(
        banner_text,
        border_style="cyan",
        expand=False,
        padding=(1, 4),
    )
    console.print(panel)

def print_authorization_warning(raw_target: str, is_authorized: bool) -> None:
    """Displays explicit legal authorization warning before active testing."""
    if not is_authorized:
        warning_text = Text()
        warning_text.append("[!] LEGAL & ETHICAL AUTHORIZATION NOTICE\n", style="bold yellow")
        warning_text.append(f"Target: {raw_target}\n\n", style="bold white")
        warning_text.append(
            "You have NOT supplied explicit authorization (--authorize). Active intrusive probing (Stage 12) will be SKIPPED.\n"
            "The scanner will proceed strictly in non-intrusive Passive Mode (reconnaissance & CVE correlation).",
            style="yellow"
        )
        console.print(Panel(warning_text, border_style="yellow", padding=(1, 2)))
    else:
        auth_text = Text()
        auth_text.append("[+] AUTHORIZED ASSESSMENT SCOPE ENGAGED\n", style="bold green")
        auth_text.append(f"Target: {raw_target}\n", style="bold white")
        auth_text.append("Explicit authorization granted. Safe Controlled Active Tests (Stage 12) are ENABLED.", style="green")
        console.print(Panel(auth_text, border_style="green", padding=(1, 2)))
