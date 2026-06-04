"""Command line interface for VigiScan."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, cast

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vigiscan import __version__
from vigiscan.modules.cve_checker import check_tech_report
from vigiscan.modules.directories import DirectoryCheckConfig, analyze_directories
from vigiscan.modules.headers import analyze_headers
from vigiscan.modules.tech_detect import analyze_technologies
from vigiscan.report import (
    ReportDocument,
    ReportFormat,
    build_report,
    save_report,
    save_reports,
)
from vigiscan.scanner import ScanRequest, ScanResult, ScannerConfig, create_scanner

REPORT_CHOICES = ("html", "json", "txt", "all")
ReportChoice = Literal["html", "json", "txt", "all"]


def build_parser() -> argparse.ArgumentParser:
    """Build the command line argument parser."""
    parser = argparse.ArgumentParser(prog="vigiscan", description="Run VigiScan.")
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to scan.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds for scanner requests. Defaults to 10.",
    )
    parser.add_argument(
        "--report",
        choices=REPORT_CHOICES,
        default="html",
        help="Report format to generate. Defaults to html.",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory where generated reports will be saved. Defaults to reports.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed execution progress.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the VigiScan CLI."""
    args = build_parser().parse_args(argv)
    console = Console()

    _render_banner(console)
    _verbose(console, args.verbose, f"Target: {args.url}")
    _verbose(console, args.verbose, f"Timeout: {args.timeout}s")

    try:
        scanner_config = ScannerConfig(timeout_seconds=args.timeout)
        directory_config = DirectoryCheckConfig(timeout_seconds=args.timeout)
    except ValueError as exc:
        console.print(f"[bold red]Configuration error[/bold red]: {exc}")
        return 1

    _verbose(console, args.verbose, "Running HTTP scanner.")
    scanner = create_scanner(scanner_config)
    scan_result = scanner.scan(ScanRequest(url=args.url))
    if not scan_result["ok"]:
        _render_scan_error(console, scan_result)
        return 1

    _verbose(console, args.verbose, "Analyzing security headers.")
    headers_report = analyze_headers(scan_result)

    _verbose(console, args.verbose, "Detecting technologies.")
    technologies_report = analyze_technologies(scan_result)

    _verbose(console, args.verbose, "Checking local CVE database.")
    cve_report = check_tech_report(technologies_report)

    _verbose(console, args.verbose, "Checking common exposed paths.")
    directories_report = analyze_directories(scan_result, config=directory_config)

    modules = {
        "headers": headers_report,
        "tech_detect": technologies_report,
        "cve_checker": cve_report,
        "directories": directories_report,
    }
    report = build_report(target_url=args.url, modules=modules)
    output = Path(args.output)
    report_paths = _save_requested_report(report, args.report, output)

    _render_summary(console, report, report_paths)
    return 0


def _save_requested_report(
    report: ReportDocument,
    report_format: ReportChoice,
    output: Path,
):
    """Save selected report format and return generated path metadata."""
    if report_format == "all":
        return save_reports(report, output_dir=output)
    selected_format = cast(ReportFormat, report_format)
    return save_report(report, selected_format, output_dir=output)


def _render_banner(console: Console) -> None:
    """Render a professional Rich banner."""
    banner = Text()
    banner.append("VigiScan", style="bold white")
    banner.append("\nWeb Security Scanner", style="cyan")
    banner.append(f"\nVersion {__version__}", style="dim")
    console.print(
        Panel(
            banner,
            title="Security Assessment",
            border_style="cyan",
            padding=(1, 2),
        ),
    )


def _render_scan_error(console: Console, scan_result: ScanResult) -> None:
    """Render a normalized scan error."""
    error = scan_result["error"] or {
        "type": "ScannerError",
        "message": "Unknown error",
    }
    console.print(
        Panel(
            f"[bold red]{error['type']}[/bold red]\n{error['message']}",
            title="Scan failed",
            border_style="red",
        ),
    )


def _render_summary(console: Console, report: ReportDocument, report_paths) -> None:
    """Render a concise CLI summary after report generation."""
    table = Table(title="VigiScan Summary", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Target", report["target_url"] or "N/A")
    table.add_row("Risk score", f"{report['risk']['score']}/100")
    table.add_row("Risk level", report["risk"]["level"])
    table.add_row("Generated", report["generated_at"])

    console.print(table)
    console.print("[bold]Executive summary[/bold]")
    console.print(report["executive_summary"]["text"])
    console.print()
    console.print("[bold]Report files[/bold]")
    if hasattr(report_paths, "txt"):
        console.print(f"- TXT: {report_paths.txt}")
        console.print(f"- JSON: {report_paths.json}")
        console.print(f"- HTML: {report_paths.html}")
    else:
        console.print(f"- {report_paths}")


def _verbose(console: Console, enabled: bool, message: str) -> None:
    """Print verbose progress when requested."""
    if enabled:
        console.print(f"[dim]>{message}[/dim]")


if __name__ == "__main__":
    raise SystemExit(main())
