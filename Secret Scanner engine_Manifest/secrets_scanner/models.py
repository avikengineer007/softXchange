"""Data models for secrets scanning engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Set


class Severity(str, Enum):
    """Severity classification for secret findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    """Confidence classification for secret findings."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleType(str, Enum):
    """Type of detection rule."""
    REGEX = "regex"
    ENTROPY = "entropy"


class ScanStatus(str, Enum):
    """Overall status of a scan.
    
    Note: FLAGGED means findings were detected at engine level. The engine reports
    facts; downstream orchestrators/policy layers decide listing blocking behavior
    based on finding severity, confidence, or allowlists.
    """
    PASSED = "passed"
    FLAGGED = "flagged"
    FAILED = "failed"
    ERROR = "error"


@dataclass(frozen=True)
class Rule:
    """Definition of a detection rule.
    
    Attributes:
        id: Unique rule identifier (e.g., 'AWS_ACCESS_KEY_ID').
        name: Short human-readable name.
        severity: Finding severity when triggered.
        description: Brief description of what this rule detects.
        rule_type: REGEX or ENTROPY.
        confidence: Baseline confidence rating (HIGH, MEDIUM, LOW).
        regex: Compiled regular expression for pattern matching (if rule_type is REGEX).
        entropy_thresholds: Dict mapping charset names ('hex', 'base64') to entropy thresholds (if rule_type is ENTROPY).
        min_entropy_len: Minimum token length for entropy evaluation.
    """
    id: str
    name: str
    severity: Severity
    description: str
    rule_type: RuleType = RuleType.REGEX
    confidence: Confidence = Confidence.HIGH
    regex: Optional[Pattern[str]] = None
    entropy_thresholds: Optional[Dict[str, float]] = None
    min_entropy_len: int = 20


@dataclass(frozen=True)
class Finding:
    """Represents a detected secret finding.
    
    Guarantees:
        `redacted_snippet` NEVER exposes unredacted secret values.
    """
    file_path: str
    line_number: int
    rule_id: str
    rule_name: str
    severity: Severity
    redacted_snippet: str
    description: str
    confidence: Confidence = Confidence.HIGH
    commit_hash: Optional[str] = None


@dataclass(frozen=True)
class SuppressedFinding:
    """Represents a finding that was suppressed by an explicit allowlist entry.
    
    Keeps audit visibility intact so reviewers can verify what was hidden.
    """
    file_path: str
    line_number: int
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: Confidence
    reason: str
    redacted_snippet: str
    commit_hash: Optional[str] = None


@dataclass(frozen=True)
class SkippedFile:
    """Represents a file or directory skipped during scanning."""
    file_path: str
    reason: str


@dataclass
class ScanResult:
    """Complete results of a package scan.
    
    Attributes:
        status: PASSED (0 findings), FLAGGED (findings detected), or FAILED (unhandled error or budget exceeded).
        success: True if scan completed without crash/error; False if scan failed.
        findings: List of all detected active secret findings.
        suppressed_findings: List of findings suppressed via explicit allowlist configuration.
        files_scanned_count: int count of successfully scanned text files.
        files_skipped: List of files/directories skipped (with reason).
        error_message: Sanitized error description if scan failed.
    """
    status: ScanStatus
    success: bool
    findings: List[Finding] = field(default_factory=list)
    suppressed_findings: List[SuppressedFinding] = field(default_factory=list)
    files_scanned_count: int = 0
    files_skipped: List[SkippedFile] = field(default_factory=list)
    error_message: Optional[str] = None
