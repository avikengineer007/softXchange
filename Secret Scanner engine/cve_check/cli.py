"""CLI entry point for CVE and dependency vulnerability checking module.

Provides human-readable output grouped by severity, JSON mode conforming to the
PackageScanResult contract, consistent exit codes (0 = passed, 1 = failed, 2 = error),
and NO_COLOR compliance.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from secrets_scanner.cli import Colors, should_use_color
from secrets_scanner.contract import PackageScanResult
from secrets_scanner.models import Severity

from .osv_client import OSVClient
from .scanner import scan_package


def format_cve_human_report(
    result: PackageScanResult,
    target_path: str,
    colors: Colors,
    title: str = "DEPENDENCY VULNERABILITY (CVE) REPORT",
) -> str:
    """Renders human-readable scan report with findings grouped by severity matching secrets-scan & static-scan."""
    lines: List[str] = []
    bar = "=" * 64

    lines.append(bar)
    lines.append(f"{colors.BOLD}{title}{colors.RESET}")
    lines.append(bar)
    lines.append(f"Target Path          : {target_path}")
    lines.append(f"Overall Status       : {colors.status(result.status)}")
    lines.append(f"Scan Duration        : {result.metadata.duration_seconds:.3f}s")
    lines.append(f"Manifests Scanned    : {result.metadata.files_scanned}")
    lines.append(f"Files Skipped        : {result.metadata.files_skipped}")

    crit_c = result.severity_counts.get("critical", 0)
    high_c = result.severity_counts.get("high", 0)
    med_c = result.severity_counts.get("medium", 0)
    low_c = result.severity_counts.get("low", 0)

    lines.append(
        f"Findings Detected    : {len(result.findings)} "
        f"({colors.RED}Critical: {crit_c}{colors.RESET}, "
        f"{colors.YELLOW}High: {high_c}{colors.RESET}, "
        f"{colors.CYAN}Medium: {med_c}{colors.RESET}, "
        f"{colors.GRAY}Low: {low_c}{colors.RESET})"
    )
    lines.append("-" * 64)

    if result.error_message:
        lines.append(f"{colors.BOLD}{colors.RED}ERROR MESSAGE:{colors.RESET} {result.error_message}")
        lines.append("-" * 64)

    # Group findings by severity order: Critical -> High -> Medium -> Low
    grouped_findings: Dict[str, List[Any]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for f in result.findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
        if sev in grouped_findings:
            grouped_findings[sev].append(f)
        else:
            grouped_findings.setdefault(sev, []).append(f)

    has_findings = False
    for sev_name in ("critical", "high", "medium", "low"):
        group = grouped_findings.get(sev_name, [])
        if not group:
            continue
        has_findings = True
        sev_label = colors.severity(sev_name)
        lines.append(f"\n{colors.BOLD}--- {sev_label} FINDINGS ({len(group)}) ---{colors.RESET}")
        for idx, f in enumerate(group, start=1):
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence).lower()
            lines.append(f"  [{idx}] {colors.BOLD}{f.rule_name}{colors.RESET} ({f.rule_id}) [Confidence: {conf_str.upper()}]")
            lines.append(f"      Location   : {f.file_path}:{f.line_number}")
            if getattr(f, "cve_id", None) and f.cve_id != f.rule_id:
                lines.append(f"      CVE ID     : {f.cve_id}")
            if getattr(f, "fixed_version", None):
                lines.append(f"      Fixed in   : {f.fixed_version}")
            snippet_str = getattr(f, "redacted_snippet", getattr(f, "snippet", ""))
            if snippet_str:
                lines.append(f"      Snippet    : {colors.DIM}{snippet_str}{colors.RESET}")
            if f.description:
                lines.append(f"      Details    : {f.description}")
            if getattr(f, "remediation_hint", None):
                lines.append(f"      {colors.GREEN}Remediation: {f.remediation_hint}{colors.RESET}")

    if not has_findings and not result.error_message:
        lines.append(f"\n{colors.GREEN}No known vulnerabilities discovered in declared dependencies.{colors.RESET}")

    lines.append("\n" + bar)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Configures command-line arguments for cve-scan CLI matching secrets-scan & static-scan design."""
    parser = argparse.ArgumentParser(
        prog="cve-scan",
        description="Audit package manifests for known vulnerabilities (CVEs) via OSV.dev batch queries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  Scan passed (no blocking vulnerabilities)
  1  Scan failed (critical/high severity findings detected)
  2  Scan error  (OSV unavailable without --fail-open, malformed manifest, or timeout)
        """,
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to manifest file or package directory to scan.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print the raw contract PackageScanResult object as formatted JSON.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Bypass the OSV TTL cache, forcing fresh remote queries.",
    )
    parser.add_argument(
        "--fail-open",
        action="store_true",
        default=False,
        help="Fail open (pass scan with warning note) if OSV.dev API is unavailable.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Network timeout in seconds for OSV batch queries (default: 10.0s).",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Optional API key / token for OSV endpoint.",
    )
    return parser


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses CLI arguments."""
    return build_parser().parse_args(args)


def main(args: Optional[List[str]] = None) -> int:
    """CLI execution entry point."""
    parsed = parse_args(args)
    target_path = Path(parsed.path).resolve()

    if not target_path.exists():
        sys.stderr.write(f"Error: Target path does not exist: {target_path}\n")
        return 2

    client = OSVClient(
        timeout=parsed.timeout,
        api_key=parsed.api_key or os.environ.get("OSV_API_KEY"),
    )

    result = scan_package(
        target_path=str(target_path),
        client=client,
        fail_open_on_osv_unavailable=parsed.fail_open,
        no_cache=parsed.no_cache,
        timeout=parsed.timeout,
    )

    if parsed.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        colors = Colors(should_use_color())
        print(format_cve_human_report(result, str(target_path), colors))

    if result.status == "error":
        return 2
    elif result.status == "failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
