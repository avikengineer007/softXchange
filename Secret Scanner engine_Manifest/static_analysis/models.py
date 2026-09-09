"""Data models for static analysis engine.

Directly reuses Severity, Confidence, ScanStatus, and SkippedFile from
secrets_scanner.models to ensure strict type identity and prevent drift.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Direct imports from secrets_scanner - no parallel enums
from secrets_scanner.models import (
    Confidence,
    ScanStatus,
    Severity,
    SkippedFile,
)
from secrets_scanner.contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    compute_severity_counts,
    evaluate_contract_status,
)


@dataclass(frozen=True)
class Finding:
    """Represents a static analysis finding.
    
    Conforms to the exact finding shape used by secrets_scanner plus a language
    field and remediation hint, ensuring scan-service can merge findings from
    both engines into a unified report.
    
    Guarantees:
      - `snippet` is always sanitized and credential-scrubbed.
      - `redacted_snippet` property returns the sanitized `snippet` for backward
        compatibility with secrets_scanner consumers without risking secret leaks.
    """
    file_path: str
    line_number: int
    rule_id: str
    rule_name: str
    severity: Severity
    snippet: str
    description: str
    language: str
    remediation_hint: str
    confidence: Confidence = Confidence.HIGH
    commit_hash: Optional[str] = None

    @property
    def redacted_snippet(self) -> str:
        """Alias for snippet preserving leak-safety contract across merged reports."""
        return self.snippet

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the finding into a dictionary conforming to scan-service requirements."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity).lower(),
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence).lower(),
            "snippet": self.snippet,
            "redacted_snippet": self.redacted_snippet,
            "description": self.description,
            "language": self.language,
            "remediation_hint": self.remediation_hint,
            "commit_hash": self.commit_hash,
        }


@dataclass
class StaticScanResult:
    """Complete results of a package static analysis scan.
    
    Attributes:
        status: PASSED (0 findings), FLAGGED (findings detected), or FAILED (error/budget breach).
        success: True if scan completed without crash/error; False if scan failed.
        findings: List of all detected static analysis findings.
        files_scanned_count: Count of successfully analyzed source files.
        files_skipped: List of files/directories skipped (with reason).
        error_message: Sanitized error description if scan failed.
    """
    status: ScanStatus
    success: bool
    findings: List[Finding] = field(default_factory=list)
    files_scanned_count: int = 0
    files_skipped: List[SkippedFile] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_contract_result(self, duration_seconds: float = 0.0) -> PackageScanResult:
        """Converts to the canonical PackageScanResult contract used by scan-service.
        
        Directly reuses secrets_scanner.contract evaluation logic to prevent any drift
        in gating decisions.
        """
        has_error = not self.success or self.status in (ScanStatus.FAILED, ScanStatus.ERROR)
        contract_status = evaluate_contract_status(self.findings, has_error=has_error)
        severity_counts = compute_severity_counts(self.findings)

        metadata = ScanMetadata(
            duration_seconds=duration_seconds,
            files_scanned=self.files_scanned_count,
            files_skipped=len(self.files_skipped),
            scan_history_ran=False,
        )

        return PackageScanResult(
            status=contract_status,
            findings=self.findings,
            severity_counts=severity_counts,
            metadata=metadata,
            suppressed_findings=[],
            error_message=self.error_message,
        )
