"""Standalone CLI entry point for the secrets-scanning engine.

Provides human-readable, color-coded output grouped by severity, JSON mode,
and standard gating exit codes (0 = passed, 1 = failed, 2 = error).
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .orchestrator import scan_package
from .contract import PackageScanResult
from .models import Finding, Severity


def should_use_color() -> bool:
    """Determines whether ANSI color codes should be rendered in terminal output.
    
    Respects the NO_COLOR standard (https://no-color.org/): if NO_COLOR is set
    and non-empty, color output is disabled. Also disables color if stdout is
    redirected / not a TTY.
    """
    if "NO_COLOR" in os.environ and os.environ["NO_COLOR"] != "":
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Colors:
    """ANSI color code container with graceful fallback to plain text."""
    
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.RESET = "\033[0m" if enabled else ""
        self.BOLD = "\033[1m" if enabled else ""
        self.DIM = "\033[2m" if enabled else ""
        self.RED = "\033[91m" if enabled else ""
        self.GREEN = "\033[92m" if enabled else ""
        self.YELLOW = "\033[93m" if enabled else ""
        self.BLUE = "\033[94m" if enabled else ""
        self.MAGENTA = "\033[95m" if enabled else ""
        self.CYAN = "\033[96m" if enabled else ""
        self.GRAY = "\033[90m" if enabled else ""

    def status(self, status_val: str) -> str:
        s = status_val.lower()
        if s == "passed":
            return f"{self.BOLD}{self.GREEN}{status_val.upper()}{self.RESET}"
        elif s == "failed":
            return f"{self.BOLD}{self.RED}{status_val.upper()}{self.RESET}"
        elif s == "error":
            return f"{self.BOLD}{self.MAGENTA}{status_val.upper()}{self.RESET}"
        return status_val.upper()

    def severity(self, sev_val: str) -> str:
        s = sev_val.lower()
        if s == "critical":
            return f"{self.BOLD}{self.RED}CRITICAL{self.RESET}"
        elif s == "high":
            return f"{self.BOLD}{self.YELLOW}HIGH{self.RESET}"
        elif s == "medium":
            return f"{self.BOLD}{self.CYAN}MEDIUM{self.RESET}"
        elif s == "low":
            return f"{self.DIM}{self.GRAY}LOW{self.RESET}"
        return sev_val.upper()


def format_human_report(result: PackageScanResult, target_dir: str, colors: Colors) -> str:
    """Renders human-readable scan report with findings grouped by severity."""
    lines: List[str] = []
    bar = "=" * 64

    lines.append(bar)
    lines.append(f"{colors.BOLD}SECRETS SCAN REPORT{colors.RESET}")
    lines.append(bar)
    lines.append(f"Target Directory     : {target_dir}")
    lines.append(f"Overall Status       : {colors.status(result.status)}")
    lines.append(f"Scan Duration        : {result.metadata.duration_seconds:.3f}s")
    lines.append(f"Files Scanned        : {result.metadata.files_scanned}")
    lines.append(f"Files Skipped        : {result.metadata.files_skipped}")
    lines.append(f"History Scanned      : {'Yes' if result.metadata.scan_history_ran else 'No'}")
    
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
            if f.commit_hash:
                lines.append(f"      Commit     : {colors.CYAN}{f.commit_hash[:12]}{colors.RESET}")
            lines.append(f"      Location   : {f.file_path}:{f.line_number}")
            lines.append(f"      Snippet    : {colors.DIM}{f.redacted_snippet}{colors.RESET}")
            lines.append(f"      Details    : {f.description}")

    if not has_findings and not result.error_message:
        lines.append(f"\n{colors.GREEN}No secrets detected.{colors.RESET}")

    if result.suppressed_findings:
        lines.append(f"\n{colors.BOLD}--- SUPPRESSED FINDINGS (ALLOWLIST AUDIT: {len(result.suppressed_findings)}) ---{colors.RESET}")
        for idx, s in enumerate(result.suppressed_findings, start=1):
            lines.append(f"  [{idx}] {s.rule_name} ({s.rule_id})")
            lines.append(f"      Location   : {s.file_path}:{s.line_number}")
            lines.append(f"      Reason     : {s.reason}")
            lines.append(f"      Snippet    : {colors.DIM}{s.redacted_snippet}{colors.RESET}")

    lines.append("\n" + bar)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="secrets-scan",
        description="Standalone secrets scanner for auditing code repositories and packages.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  Scan passed (no blocking findings)
  1  Scan failed (critical/high severity with high confidence detected)
  2  Scan error  (scan budget breach, git error, or unhandled exception)
        """
    )
    parser.add_argument(
        "path",
        type=str,
        help="Target directory path to scan."
    )
    parser.add_argument(
        "--history",
        "--scan-history",
        dest="history",
        action="store_true",
        default=False,
        help="Inspect git commit history and diffs if .git exists."
    )
    parser.add_argument(
        "--allowlist",
        "--allowlist-config",
        dest="allowlist",
        type=str,
        default=None,
        help="Path to JSON allowlist configuration file to suppress known false positives."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print the raw result object from Prompt 4 as formatted JSON."
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=500,
        help="Maximum commits to scan in git history (default: 500)."
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=5 * 1024 * 1024,
        help="Maximum individual file size in bytes (default: 5MB)."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Scan wall-clock timeout budget in seconds (default: 30.0s)."
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point returning exit code (0 = passed, 1 = failed, 2 = error)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    result = scan_package(
        target_dir=args.path,
        allowlist_config=args.allowlist,
        scan_history=args.history,
        max_commits=args.max_commits,
        max_file_size=args.max_file_size,
        timeout_seconds=args.timeout,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        colors = Colors(enabled=should_use_color())
        print(format_human_report(result, args.path, colors))

    # Exit code contract:
    # 0 = passed
    # 1 = failed
    # 2 = error
    if result.status == "error":
        return 2
    elif result.status == "failed":
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
