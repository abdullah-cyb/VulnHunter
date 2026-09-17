"""Command Line Interface for ABDULLAH.CYB VULNHUNTER."""

import sys
import argparse
import asyncio
from pathlib import Path
from typing import Optional

from vulnhunter import __version__
from vulnhunter.core.target import parse_target
from vulnhunter.core.models import ScanMode
from vulnhunter.core.engine import VulnHunterEngine
from vulnhunter.intel.db import IntelDatabase
from vulnhunter.intel.sync import sync_all_intelligence
from vulnhunter.ui.banner import print_banner, print_authorization_warning
from vulnhunter.ui.console import display_findings_summary, display_detailed_finding
from vulnhunter.core.config import DEFAULT_REPORTS_DIR

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="ABDULLAH.CYB VULNHUNTER - Autonomous Vulnerability Discovery & Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument("-t", "--target", type=str, help="Target host, IP address, URL, or CIDR network block")
    parser.add_argument("-a", "--authorize", action="store_true", help="Grant explicit authorization for controlled active verification probes")
    parser.add_argument("-m", "--mode", choices=["PASSIVE", "STANDARD", "DEEP"], default="STANDARD", help="Scan intensity mode (default: STANDARD)")
    parser.add_argument("-o", "--output", type=str, help="Output directory path for JSON & HTML reports (default: ~/.vulnhunter/reports)")
    parser.add_argument("--sync-intel", action="store_true", help="Synchronize local vulnerability database with online feeds (CISA KEV, OSV)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv)")
    parser.add_argument("--version", action="version", version=f"VulnHunter {__version__}")
    
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    # Handle intelligence sync command
    if args.sync_intel:
        db = IntelDatabase()
        print("[*] Synchronizing local vulnerability intelligence database...")
        res = asyncio.run(sync_all_intelligence(db))
        print(f"[✓] Intelligence sync complete! {res['cisa_kev_records_synced']} KEV records cached locally.")
        if not args.target:
            sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    scan_mode_enum = ScanMode(args.mode)
    target_config = parse_target(args.target, is_authorized=args.authorize, scan_mode=scan_mode_enum)

    print_authorization_warning(target_config.raw_target, target_config.is_authorized)

    output_dir = Path(args.output) if args.output else DEFAULT_REPORTS_DIR

    # Execute Autonomous 15-Stage Scan
    engine = VulnHunterEngine(target_config)
    report = asyncio.run(engine.execute_scan(output_dir=output_dir))

    # Render summary and detailed finding breakdowns
    display_findings_summary(report)

    for f in report.findings[:3]:  # Show top 3 detailed breakdowns in console
        display_detailed_finding(f)

    print(f"\n[✓] Full scan report exported to: {output_dir}\n")

if __name__ == "__main__":
    main()
