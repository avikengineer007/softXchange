"""Orchestrator entry point providing a decoupled interface for scan-service."""

import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Union

from .contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    compute_severity_counts,
    evaluate_contract_status,
)
from .scanner import SecretsScanner
from .models import ScanStatus


def scan_package(
    target_dir: Union[str, Path],
    allowlist_config: Optional[Any] = None,
    scan_history: bool = False,
    max_commits: int = 500,
    timeout_seconds: Optional[float] = 30.0,
    max_file_size: int = 5 * 1024 * 1024,
    max_total_bytes: int = 100 * 1024 * 1024,
    max_total_files: int = 5000,
    block_on_medium_confidence_critical: bool = False,
    **kwargs: Any,
) -> PackageScanResult:
    """Canonical entry point invoked by the scan-service rules orchestrator.
    
    This function has zero coupling to listings, sellers, or marketplace entities.
    It takes a filesystem directory path, executes secrets detection with fail-closed
    safety, evaluates gating status, and returns a structured PackageScanResult.

    Args:
        target_dir: Directory path of the unpacked package to scan.
        allowlist_config: Optional allowlist configuration file path or object.
        scan_history: Whether to walk git commit history if .git exists (default False).
        max_commits: Maximum git commits to walk (default 500).
        timeout_seconds: Wall-clock timeout budget for scan in seconds (default 30.0s).
        max_file_size: Maximum individual file size in bytes (default 5MB).
        max_total_bytes: Total decompressed scan byte limit (default 100MB).
        max_total_files: Maximum number of files processed (default 5,000).
        block_on_medium_confidence_critical: Whether critical severity findings with
            medium confidence should also fail the scan (default False).
        **kwargs: Additional engine options (e.g. rules catalog overrides).

    Returns:
        PackageScanResult conforming to the scan-service contract.
    """
    start_time = time.monotonic()

    try:
        scanner = SecretsScanner(
            max_file_size=max_file_size,
            max_total_bytes=max_total_bytes,
            max_total_files=max_total_files,
            timeout_seconds=timeout_seconds,
            allowlist_config=allowlist_config,
            scan_history=scan_history,
            max_commits=max_commits,
            **kwargs,
        )

        engine_result = scanner.scan_directory(str(target_dir))
        duration = time.monotonic() - start_time

        has_error = not engine_result.success or engine_result.status == ScanStatus.FAILED
        status = evaluate_contract_status(
            findings=engine_result.findings,
            has_error=has_error,
            block_on_medium_confidence_critical=block_on_medium_confidence_critical,
        )

        severity_counts = compute_severity_counts(engine_result.findings)

        metadata = ScanMetadata(
            duration_seconds=duration,
            files_scanned=engine_result.files_scanned_count,
            files_skipped=len(engine_result.files_skipped),
            scan_history_ran=bool(scan_history and (Path(target_dir) / ".git").exists()),
        )

        return PackageScanResult(
            status=status,
            findings=engine_result.findings,
            severity_counts=severity_counts,
            metadata=metadata,
            suppressed_findings=engine_result.suppressed_findings,
            error_message=engine_result.error_message,
        )

    except Exception as e:
        duration = time.monotonic() - start_time
        return PackageScanResult(
            status=ContractStatus.ERROR.value,
            findings=[],
            severity_counts=compute_severity_counts([]),
            metadata=ScanMetadata(
                duration_seconds=duration,
                files_scanned=0,
                files_skipped=0,
                scan_history_ran=False,
            ),
            suppressed_findings=[],
            error_message=f"UnhandledScanError: {type(e).__name__}: {str(e)}",
        )
