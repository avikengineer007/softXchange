"""Data models for CVE and dependency vulnerability checking module.

Directly reuses Severity, Confidence, ScanStatus, and SkippedFile from
secrets_scanner.models, and PackageScanResult, ScanMetadata,
evaluate_contract_status, and compute_severity_counts from
secrets_scanner.contract to maintain unified contract consistency.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Direct imports from secrets_scanner - strict reuse discipline, no parallel definitions
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
class CVEFinding:
    """Represents a discovered CVE / vulnerability in a declared dependency.
    
    Conforms to the Finding interface expected by PackageScanResult and
    the rest of the scanner engine pipeline.
    """
    file_path: str
    line_number: int
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    package_name: str
    ecosystem: str
    version: Optional[str] = None
    cve_id: Optional[str] = None
    osv_id: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    snippet: str = ""
    remediation_hint: str = ""
    confidence: Confidence = Confidence.HIGH
    commit_hash: Optional[str] = None

    @property
    def redacted_snippet(self) -> str:
        """Compatibility property matching the PackageScanResult contract."""
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
            "commit_hash": self.commit_hash,
            "redacted_snippet": self.redacted_snippet,
            "description": self.description,
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "cve_id": self.cve_id,
            "osv_id": self.osv_id,
            "aliases": list(self.aliases),
            "fixed_version": self.fixed_version,
            "remediation_hint": self.remediation_hint,
        }


# Direct reuse of StaticScanResult from static_analysis to avoid duplicate result classes
from static_analysis.models import StaticScanResult

# CVEScanResult aliases StaticScanResult for drop-in shape compatibility
CVEScanResult = StaticScanResult

# Alias Finding to CVEFinding for drop-in consistency with secrets_scanner and static_analysis
Finding = CVEFinding

__all__ = [
    "Confidence",
    "ContractStatus",
    "CVEFinding",
    "CVEScanResult",
    "Finding",
    "PackageScanResult",
    "ScanMetadata",
    "ScanStatus",
    "Severity",
    "SkippedFile",
    "StaticScanResult",
    "compute_severity_counts",
    "evaluate_contract_status",
]

