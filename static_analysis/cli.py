"""CLI entry point for the static analysis engine and combined security scanner.

Provides human-readable output grouped by severity, JSON mode conforming to the
PackageScanResult contract, consistent exit codes (0 = passed, 1 = failed, 2 = error),
and an optional --with-secrets-scan mode to preview scan-service multi-scanner execution.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from secrets_scanner.cli import Colors, should_use_color
from secrets_scanner.contract import PackageScanResult, merge_package_results
from secrets_scanner.models import Finding, Severity
from secrets_scanner.orchestrator import scan_package as scan_secrets_package
from .scanner import scan_package as scan_static_package


def format_static_human_report(
    result: PackageScanResult,
    target_dir: str,
    colors: Colors,
    title: str = "STATIC ANALYSIS SCAN REPORT",
) -> str:
    """Renders human-readable scan report with findings grouped by severity matching secrets-scan."""
    lines: List[str] = []
    bar = "=" * 64

    lines.append(bar)
    lines.append(f"{colors.BOLD}{title}{colors.RESET}")
    lines.append(bar)
    lines.append(f"Target Directory     : {target_dir}")
    lines.append(f"Overall Status       : {colors.status(result.status)}")
    lines.append(f"Scan Duration        : {result.metadata.duration_seconds:.3f}s")
    lines.append(f"Files Scanned        : {result.metadata.files_scanned}")
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
    if result.suppressed_findings:
        lines.append(f"Findings Suppressed  : {len(result.suppressed_findings)} (Allowlist)")
    lines.append("-" * 64)

    if result.error_message:
        lines.append(f"{colors.BOLD}{colors.RED}ERROR MESSAGE:{colors.RESET} {result.error_message}")
        lines.append("-" * 64)

    # Group findings by severity order: Critical -> High -> Medium -> Low
    grouped_findings: Dict[str, List[Finding]] = {
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
            lang = getattr(f, "language", None)
            if lang:
                lines.append(f"      Language   : {lang}")
            snippet_str = getattr(f, "redacted_snippet", getattr(f, "snippet", ""))
            lines.append(f"      Snippet    : {colors.DIM}{snippet_str}{colors.RESET}")
            lines.append(f"      Details    : {f.description}")
            remediation = getattr(f, "remediation_hint", None)
            if remediation:
                lines.append(f"      {colors.GREEN}Remediation: {remediation}{colors.RESET}")

    if not has_findings and not result.error_message:
        lines.append(f"\n{colors.GREEN}No violations detected.{colors.RESET}")

    lines.append("\n" + bar)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser matching secrets-scan."""
    parser = argparse.ArgumentParser(
        prog="static-scan",
        description="Deterministic, rule-based static analysis & dependency manifest scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  Scan passed (no blocking findings)
  1  Scan failed (critical/high severity with high confidence detected)
  2  Scan error  (malformed manifest, unhandled exception, or timeout)
        """
    )
    parser.add_argument(
        "path",
        type=str,
        help="Target directory path or file to scan."
    )
    parser.add_argument(
        "--check-dependencies",
        dest="check_dependencies",
        action="store_true",
        default=True,
        help="Inspect package dependency manifests for malicious packages and unpinned versions (default: True)."
    )
    parser.add_argument(
        "--no-check-dependencies",
        "--no-manifests",
        "--skip-manifests",
        dest="check_dependencies",
        action="store_false",
        help="Skip dependency manifest inspection pass (source code rules only)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print the raw contract PackageScanResult object as formatted JSON."
    )
    parser.add_argument(
        "--with-secrets-scan",
        action="store_true",
        default=False,
        help="Run both static analysis and secrets scanner together, outputting the merged scan-service report."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Scan wall-clock timeout budget in seconds (default: 30.0s)."
    )
    parser.add_argument(
        "--denylist",
        type=str,
        default=None,
        help="Custom path to malicious package denylist JSON file."
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point returning exit code (0 = passed, 1 = failed, 2 = error)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.with_secrets_scan:
        # Run static analysis
        static_result = scan_static_package(
            target_dir=args.path,
            timeout_seconds=args.timeout,
            check_dependency_manifests=args.check_dependencies,
            denylist_path=args.denylist,
        )
        # Run secrets scan
        secrets_result = scan_secrets_package(
            target_dir=args.path,
            timeout_seconds=args.timeout,
        )
        # Merge using canonical merge logic
        result = merge_package_results(secrets_result, static_result)
        report_title = "COMBINED SECURITY SCAN REPORT (SECRETS + STATIC ANALYSIS)"
    else:
        result = scan_static_package(
            target_dir=args.path,
            timeout_seconds=args.timeout,
            check_dependency_manifests=args.check_dependencies,
            denylist_path=args.denylist,
        )
        report_title = "STATIC ANALYSIS SCAN REPORT"

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        colors = Colors(enabled=should_use_color())
        print(format_static_human_report(result, args.path, colors, title=report_title))

    if result.status == "error":
        return 2
    elif result.status == "failed":
        return 1
    return 0


def main_combined(argv: Optional[List[str]] = None) -> int:
    """Dedicated combined scanner entry point that runs both modules together."""
    args_list = list(argv) if argv is not None else sys.argv[1:]
    if "--with-secrets-scan" not in args_list:
        args_list.append("--with-secrets-scan")
    return main(args_list)


if __name__ == "__main__":
    sys.exit(main())
