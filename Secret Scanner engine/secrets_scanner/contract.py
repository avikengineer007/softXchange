"""Contract data models and evaluation logic for scan-service integration."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .models import Confidence, Finding, Severity, SuppressedFinding


class ContractStatus(str, Enum):
    """Gating statuses recognized by the scan-service rules orchestrator."""
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass
class ScanMetadata:
    """Operational telemetry and metadata for the scan execution."""
    duration_seconds: float
    files_scanned: int
    files_skipped: int
    scan_history_ran: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_seconds": round(self.duration_seconds, 4),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "scan_history_ran": self.scan_history_ran,
        }


@dataclass
class PackageScanResult:
    """Canonical scan result contract conforming to scan-service requirements.
    
    Acts as the single source of truth for the secrets scanner module.
    """
    status: str  # "passed" | "failed" | "error"
    findings: List[Finding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    })
    metadata: ScanMetadata = field(
        default_factory=lambda: ScanMetadata(
            duration_seconds=0.0,
            files_scanned=0,
            files_skipped=0,
            scan_history_ran=False,
        )
    )
    suppressed_findings: List[SuppressedFinding] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the scan result into a clean, JSON-serializable dictionary."""
        return {
            "status": self.status,
            "findings": [
                {
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower(),
                    "confidence": f.confidence.value if isinstance(f.confidence, Confidence) else str(f.confidence).lower(),
                    "commit_hash": f.commit_hash,
                    "redacted_snippet": f.redacted_snippet,
                    "description": f.description,
                }
                for f in self.findings
            ],
            "severity_counts": dict(self.severity_counts),
            "metadata": self.metadata.to_dict(),
            "suppressed_findings": [
                {
                    "file_path": s.file_path,
                    "line_number": s.line_number,
                    "rule_id": s.rule_id,
                    "rule_name": s.rule_name,
                    "severity": s.severity.value if isinstance(s.severity, Severity) else str(s.severity).lower(),
                    "confidence": s.confidence.value if isinstance(s.confidence, Confidence) else str(s.confidence).lower(),
                    "commit_hash": s.commit_hash,
                    "reason": s.reason,
                    "redacted_snippet": s.redacted_snippet,
                }
                for s in self.suppressed_findings
            ],
            "error_message": self.error_message,
        }


def compute_severity_counts(findings: List[Finding]) -> Dict[str, int]:
    """Calculates total finding counts grouped by severity."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def evaluate_contract_status(
    findings: List[Finding],
    has_error: bool = False,
    block_on_medium_confidence_critical: bool = False,
) -> str:
    """Evaluates the final gating status based on findings and execution health.
    
    Status Logic:
    1. Unhandled error (timeout, budget exceeded, git failure, crash) -> "error"
       (The calling service must treat "error" the same as "failed" for gating).
    2. Any finding with severity in ("critical", "high") AND confidence == "high" -> "failed".
    3. Optional flag block_on_medium_confidence_critical: if enabled, also fails on
       critical severity with medium confidence (e.g. hardcoded passwords).
    4. All other findings (medium/low severity or medium/low confidence) -> "passed"
       (findings remain included in the result for seller visibility without blocking).
    """
    if has_error:
        return ContractStatus.ERROR.value

    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
        conf = f.confidence.value if isinstance(f.confidence, Confidence) else str(f.confidence).lower()

        if sev in ("critical", "high") and conf == "high":
            return ContractStatus.FAILED.value

        if block_on_medium_confidence_critical and sev == "critical" and conf == "medium":
            return ContractStatus.FAILED.value

    return ContractStatus.PASSED.value


def merge_package_results(
    first_result: PackageScanResult,
    *other_results: PackageScanResult,
) -> PackageScanResult:
    """Merges multiple PackageScanResult objects into one combined PackageScanResult.

    Status Decision Logic (Fail-Closed):
      - 'error': if any scanner failed with an unhandled exception or error
      - 'failed': if any scanner detected high/critical severity + high confidence findings
      - 'passed': if all scanners passed (findings remain included for seller review)

    Aggregations:
      - findings: union of all findings from all scanners
      - severity_counts: sum of findings across all severity levels (critical, high, medium, low)
      - metadata: summed duration, scanned files count, and skipped files count
      - suppressed_findings: union of all suppressed findings
      - error_message: joined error descriptions if any
    """
    all_results = [first_result] + list(other_results)

    if any(r.status == ContractStatus.ERROR.value for r in all_results):
        overall_status = ContractStatus.ERROR.value
    elif any(r.status == ContractStatus.FAILED.value for r in all_results):
        overall_status = ContractStatus.FAILED.value
    else:
        overall_status = ContractStatus.PASSED.value

    merged_findings = []
    merged_suppressed = []
    merged_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_duration = 0.0
    total_scanned = 0
    total_skipped = 0
    scan_history_ran = False
    errs = []

    for res in all_results:
        merged_findings.extend(res.findings)
        merged_suppressed.extend(res.suppressed_findings)
        for sev, count in res.severity_counts.items():
            s_low = sev.lower()
            merged_counts[s_low] = merged_counts.get(s_low, 0) + count

        total_duration += res.metadata.duration_seconds
        total_scanned += res.metadata.files_scanned
        total_skipped += res.metadata.files_skipped
        scan_history_ran = scan_history_ran or res.metadata.scan_history_ran

        if res.error_message:
            errs.append(res.error_message)

    combined_metadata = ScanMetadata(
        duration_seconds=round(total_duration, 4),
        files_scanned=total_scanned,
        files_skipped=total_skipped,
        scan_history_ran=scan_history_ran,
    )
    combined_error = "; ".join(errs) if errs else None

    return PackageScanResult(
        status=overall_status,
        findings=merged_findings,
        severity_counts=merged_counts,
        metadata=combined_metadata,
        suppressed_findings=merged_suppressed,
        error_message=combined_error,
    )


# Alias for callers expecting merge_scan_results(secrets_result, static_result)
merge_scan_results = merge_package_results
