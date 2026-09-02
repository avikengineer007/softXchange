"""Deterministic, rule-based static analysis engine module.

Matching the architecture of secrets_scanner and designed for unified reporting
in scan-service.
"""

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
    merge_package_results,
    merge_scan_results,
)

from .languages import (
    DEFAULT_LANGUAGE_REGISTRY,
    Language,
    LanguageDefinition,
    LanguageRegistry,
)
from .manifests import (
    DeclaredDependency,
    ManifestInspectionResult,
    inspect_manifest,
    is_manifest_file,
    load_denylist,
)
from .matchers import (
    BaseMatcher,
    ContextAwareRegexMatcher,
    MatchResult,
    ObfuscationMatcher,
    RegexMatcher,
)
from .models import (
    Finding,
    StaticScanResult,
)
from .rules import (
    Rule,
    get_default_rules,
)
from .sanitizer import (
    sanitize_snippet,
    scrub_credentials,
)
from .scanner import (
    StaticAnalyzer,
    scan_directory,
    scan_package,
)

__all__ = [
    "BaseMatcher",
    "Confidence",
    "ContextAwareRegexMatcher",
    "ContractStatus",
    "DEFAULT_LANGUAGE_REGISTRY",
    "DeclaredDependency",
    "Finding",
    "Language",
    "LanguageDefinition",
    "LanguageRegistry",
    "ManifestInspectionResult",
    "MatchResult",
    "ObfuscationMatcher",
    "PackageScanResult",
    "RegexMatcher",
    "Rule",
    "ScanMetadata",
    "ScanStatus",
    "Severity",
    "SkippedFile",
    "StaticAnalyzer",
    "StaticScanResult",
    "get_default_rules",
    "inspect_manifest",
    "is_manifest_file",
    "load_denylist",
    "merge_package_results",
    "merge_scan_results",
    "sanitize_snippet",
    "scan_directory",
    "scan_package",
    "scrub_credentials",
]
