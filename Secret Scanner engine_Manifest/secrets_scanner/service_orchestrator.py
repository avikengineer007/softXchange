"""Post-intake scan-service orchestrator.

Coordinates:
- Multi-scanner execution over an intake scratch directory (defaulting to secrets_scanner.scan_package).
- Result aggregation: union of findings, sum of severity counts, and fail-closed status evaluation.
- Storage transitions: moves package from pending/ to live/{listing_id}/{version}/ in object storage on passed.
- Database persistence: updates Postgres status to 'live' on pass, 'scan_failed' on fail/error,
  and stores full findings and severity counts for seller visibility.
- Guaranteed scratch working directory deletion across all outcomes, including scanner exceptions.
- Single clear entry point: process_upload(listing_id, version, scratch_dir).
"""

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, Union, runtime_checkable

from .contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    compute_severity_counts,
    merge_package_results,
)
from .intake import safe_rmtree
from .models import Finding, SuppressedFinding
from .orchestrator import scan_package
from static_analysis.scanner import scan_package as scan_static_package
from cve_check.scanner import scan_package as scan_cve_package

logger = logging.getLogger("scan_service.orchestrator")


# -----------------------------------------------------------------------------
# Storage and Repository Protocols (Dependency Injection)
# -----------------------------------------------------------------------------

@runtime_checkable
class ObjectStorageClient(Protocol):
    """Protocol for object storage interactions (e.g. S3 / GCS)."""

    def move_package(self, source_prefix: str, destination_prefix: str) -> None:
        """Moves package contents from source_prefix to destination_prefix."""
        ...

    def package_exists(self, prefix: str) -> bool:
        """Checks if package contents exist at the specified prefix."""
        ...


@runtime_checkable
class ListingRepository(Protocol):
    """Protocol for persisting listing versions and scan results (e.g. Postgres)."""

    def update_status_and_results(
        self,
        listing_id: str,
        version: str,
        status: str,
        scan_result: Dict[str, Any],
        storage_location: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Updates listing version status, storage location, and scan results."""
        ...

    def get_listing_version(self, listing_id: str, version: str) -> Optional[Dict[str, Any]]:
        """Retrieves a listing version record."""
        ...


class InMemoryObjectStorage(ObjectStorageClient):
    """In-memory object storage double for testing and development."""

    def __init__(self, initial_packages: Optional[Dict[str, bytes]] = None):
        # Maps path/prefix to dummy object content or metadata
        self.store: Dict[str, bytes] = initial_packages or {}

    def move_package(self, source_prefix: str, destination_prefix: str) -> None:
        src = source_prefix.rstrip("/") + "/"
        dst = destination_prefix.rstrip("/") + "/"
        keys_to_move = [k for k in self.store if k.startswith(src) or k == source_prefix.rstrip("/")]
        
        if not keys_to_move:
            # If tracking prefix itself as an entry
            if source_prefix in self.store:
                self.store[destination_prefix] = self.store.pop(source_prefix)
                return
            # Create destination placeholder if src was conceptual
            self.store[dst] = b"package-payload"
            return

        for k in keys_to_move:
            rel = k[len(src):]
            new_key = dst + rel
            self.store[new_key] = self.store.pop(k)

    def package_exists(self, prefix: str) -> bool:
        pref = prefix.rstrip("/")
        return any(k.startswith(pref) for k in self.store)


class InMemoryPostgresListingRepository(ListingRepository):
    """In-memory Postgres repository double for testing and development."""

    def __init__(self):
        self.records: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def update_status_and_results(
        self,
        listing_id: str,
        version: str,
        status: str,
        scan_result: Dict[str, Any],
        storage_location: str,
        error_message: Optional[str] = None,
    ) -> None:
        key = (listing_id, version)
        rec = self.records.get(key, {
            "listing_id": listing_id,
            "version": version,
            "created_at": time.time(),
        })
        rec.update({
            "status": status,
            "scan_result": scan_result,
            "storage_location": storage_location,
            "error_message": error_message,
            "updated_at": time.time(),
        })
        self.records[key] = rec

    def get_listing_version(self, listing_id: str, version: str) -> Optional[Dict[str, Any]]:
        return self.records.get((listing_id, version))


# -----------------------------------------------------------------------------
# Scanner Composition & Result Aggregation
# -----------------------------------------------------------------------------

# Callable signature for individual scanners
ScannerCallable = Callable[..., PackageScanResult]

# Default list of scanners executed by the orchestrator
DEFAULT_SCANNERS: List[ScannerCallable] = [
    scan_package,
    scan_static_package,
    scan_cve_package,
]


@dataclass
class ScanOutcome:
    """Canonical outcome of orchestrator execution.
    
    Attributes:
        listing_id: Marketplace listing ID.
        version: Version string.
        status: Final Postgres status ('live' if passed, 'scan_failed' if blocked).
        overall_scan_status: Raw combined scanner status ('passed', 'failed', 'error').
        findings: Merged union of all findings across all executed scanners.
        severity_counts: Aggregated severity counts summed across all scanners.
        suppressed_findings: Merged union of suppressed findings across scanners.
        storage_location: Final object storage location (live/... or pending/...).
        scanner_results: Individual results from each executed scanner.
        error_message: Sanitized error description if any scanner or worker errored.
    """
    listing_id: str
    version: str
    status: str
    overall_scan_status: str
    findings: List[Finding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0
    })
    suppressed_findings: List[SuppressedFinding] = field(default_factory=list)
    storage_location: str = ""
    scanner_results: List[PackageScanResult] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Safe dictionary representation suitable for API / seller dashboard view."""
        return {
            "listing_id": self.listing_id,
            "version": self.version,
            "status": self.status,
            "overall_scan_status": self.overall_scan_status,
            "findings": [
                {
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": getattr(f.severity, "value", str(f.severity)).lower(),
                    "confidence": getattr(f.confidence, "value", str(f.confidence)).lower(),
                    "commit_hash": f.commit_hash,
                    "redacted_snippet": f.redacted_snippet,
                    "description": f.description,
                }
                for f in self.findings
            ],
            "severity_counts": dict(self.severity_counts),
            "suppressed_findings_count": len(self.suppressed_findings),
            "storage_location": self.storage_location,
            "scanner_count": len(self.scanner_results),
            "error_message": self.error_message,
        }


def merge_scan_results(
    results_or_first: Union[List[PackageScanResult], PackageScanResult],
    second: Optional[PackageScanResult] = None,
) -> Any:
    """Aggregates multiple PackageScanResult objects into a combined result.
    
    Usage:
      1. Two results: merge_scan_results(secrets_res, static_res) -> PackageScanResult
      2. List of results: merge_scan_results([res1, res2, ...]) -> Tuple[status, findings, counts, suppressed, error_messages]
    
    Aggregation Rules:
      1. Fail-closed status:
         - Any scanner status == 'error' -> overall 'error'
         - Else any scanner status == 'failed' -> overall 'failed'
         - Else (all 'passed') -> overall 'passed'
      2. Findings:
         - Union list of all findings across all scanners.
      3. Severity counts:
         - Exact sum across all scanners for each severity tier (critical, high, medium, low).
      4. Suppressed findings:
         - Union list of all suppressed findings.
      5. Error messages:
         - List of error messages from any failing scanner.
    """
    if second is not None or isinstance(results_or_first, PackageScanResult):
        if second is None:
            raise ValueError("Expected second PackageScanResult when merging two results")
        return merge_package_results(results_or_first, second)

    results = results_or_first
    if not results:
        return (ContractStatus.PASSED.value, [], {"critical": 0, "high": 0, "medium": 0, "low": 0}, [], [])

    merged_findings: List[Finding] = []
    merged_suppressed: List[SuppressedFinding] = []
    merged_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    error_messages: List[str] = []
    has_error = False
    has_failed = False

    for r in results:
        merged_findings.extend(r.findings)
        merged_suppressed.extend(r.suppressed_findings)
        
        for sev, count in r.severity_counts.items():
            s_low = sev.lower()
            merged_counts[s_low] = merged_counts.get(s_low, 0) + count

        if r.status == ContractStatus.ERROR.value:
            has_error = True
            if r.error_message:
                error_messages.append(r.error_message)
        elif r.status == ContractStatus.FAILED.value:
            has_failed = True

    if has_error:
        overall_status = ContractStatus.ERROR.value
    elif has_failed:
        overall_status = ContractStatus.FAILED.value
    else:
        overall_status = ContractStatus.PASSED.value

    return overall_status, merged_findings, merged_counts, merged_suppressed, error_messages


# -----------------------------------------------------------------------------
# Main Orchestrator Entry Point
# -----------------------------------------------------------------------------

def process_upload(
    listing_id: str,
    version: str,
    scratch_dir: Union[str, Path],
    scanners: Optional[List[ScannerCallable]] = None,
    storage_client: Optional[ObjectStorageClient] = None,
    repository: Optional[ListingRepository] = None,
    **scan_kwargs: Any,
) -> ScanOutcome:
    """Canonical post-intake scanning orchestrator entry point.
    
    Trust Boundary Note:
        This function receives a scratch_dir directly from an intake boundary (such
        as IntakePipeline, which has already safely extracted archives or cloned repos).
        process_upload assumes the scratch directory path is isolated and safe, and is
        responsible for scanning, gating, storage transitions, and final cleanup.
        
    Workflow:
      1. Executes all configured scanners sequentially over scratch_dir (defaults to
         [secrets_scanner.scan_package]).
      2. Aggregates results: unions findings, sums severity counts, and resolves overall status.
      3. Gating & Transitions:
         - 'passed': moves package in object storage to 'live/{listing_id}/{version}/',
           updates Postgres status to 'live', and stores results for seller viewing.
         - 'failed': leaves package in 'pending/', updates Postgres status to 'scan_failed',
           and stores full findings so the seller sees what blocked it.
         - 'error': same as failed — leaves package in 'pending/', status 'scan_failed'
           (fail-closed guarantee).
      4. Always deletes scratch_dir in a finally block regardless of outcome or unhandled exception.
      
    Args:
        listing_id: Marketplace listing identifier.
        version: Listing version string (e.g. 'v1', commit SHA).
        scratch_dir: Working filesystem directory containing unpacked/cloned files.
        scanners: List of scanner callables to run (defaults to DEFAULT_SCANNERS).
        storage_client: Optional ObjectStorageClient double or client.
        repository: Optional ListingRepository double or client.
        **scan_kwargs: Additional kwargs passed to individual scanners.
        
    Returns:
        ScanOutcome summarizing the gating decision, storage path, and findings.
    """
    storage = storage_client or InMemoryObjectStorage()
    repo = repository or InMemoryPostgresListingRepository()
    scanner_list = scanners if scanners is not None else DEFAULT_SCANNERS
    
    pending_prefix = f"pending/{listing_id}/{version}"
    live_prefix = f"live/{listing_id}/{version}"
    
    scanner_results: List[PackageScanResult] = []
    scratch_path = Path(scratch_dir).resolve()
    
    try:
        # 1. Execute all configured scanners sequentially
        for scanner_fn in scanner_list:
            try:
                res = scanner_fn(str(scratch_path), **scan_kwargs)
                scanner_results.append(res)
            except Exception as e:
                logger.exception("Scanner %s raised unhandled exception on %s", getattr(scanner_fn, "__name__", str(scanner_fn)), scratch_path)
                # Fail-closed on scanner crash: construct an error PackageScanResult
                err_res = PackageScanResult(
                    status=ContractStatus.ERROR.value,
                    findings=[],
                    severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
                    error_message=f"ScannerException ({getattr(scanner_fn, '__name__', 'scanner')}): {type(e).__name__}: {str(e)}",
                )
                scanner_results.append(err_res)

        # 2. Merge all scanner outputs
        overall_status, merged_findings, merged_counts, merged_suppressed, errors = merge_scan_results(scanner_results)
        combined_error_msg = "; ".join(errors) if errors else None

        # 3. Apply gating decisions, storage moves, and Postgres updates
        if overall_status == ContractStatus.PASSED.value:
            # Move from pending/ to live/ in object storage
            storage.move_package(pending_prefix, live_prefix)
            final_storage = f"{live_prefix}/"
            postgres_status = "live"
        else:
            # Leave package in pending/ (never live/), fail-closed
            final_storage = f"{pending_prefix}/"
            postgres_status = "scan_failed"

        outcome = ScanOutcome(
            listing_id=listing_id,
            version=version,
            status=postgres_status,
            overall_scan_status=overall_status,
            findings=merged_findings,
            severity_counts=merged_counts,
            suppressed_findings=merged_suppressed,
            storage_location=final_storage,
            scanner_results=scanner_results,
            error_message=combined_error_msg,
        )

        # Update database with seller-facing result
        repo.update_status_and_results(
            listing_id=listing_id,
            version=version,
            status=postgres_status,
            scan_result=outcome.to_dict(),
            storage_location=final_storage,
            error_message=combined_error_msg,
        )

        return outcome

    except Exception as e:
        logger.exception("Fatal unhandled exception in process_upload for %s %s", listing_id, version)
        fallback_storage = f"{pending_prefix}/"
        fallback_status = "scan_failed"
        fallback_outcome = ScanOutcome(
            listing_id=listing_id,
            version=version,
            status=fallback_status,
            overall_scan_status=ContractStatus.ERROR.value,
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            storage_location=fallback_storage,
            scanner_results=scanner_results,
            error_message=f"OrchestratorException: {type(e).__name__}: {str(e)}",
        )
        try:
            repo.update_status_and_results(
                listing_id=listing_id,
                version=version,
                status=fallback_status,
                scan_result=fallback_outcome.to_dict(),
                storage_location=fallback_storage,
                error_message=fallback_outcome.error_message,
            )
        except Exception:
            pass
        return fallback_outcome

    finally:
        # 4. Cleanup Guarantee: Delete scratch working directory in all cases
        safe_rmtree(scratch_path)
