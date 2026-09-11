"""CVE and dependency vulnerability checking module for scan engine.

Matching the architecture and standards of secrets_scanner and static_analysis.
Integrates with OSV.dev via batch queries to audit declared package dependencies.
"""

# Direct reuse from secrets_scanner
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

# Direct reuse from static_analysis.manifests
from static_analysis.manifests import (
    DeclaredDependency,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_requirements_txt,
)

# CVE module components
from .cache import DEFAULT_OSV_CACHE, OSVCache
from .models import (
    CVEFinding,
    CVEScanResult,
    Finding,
)
from .osv_client import (
    ECOSYSTEM_MAPPING,
    OSVClient,
    OSVClientError,
    OSVConnectionError,
    OSVHTTPError,
    OSVResponseError,
    OSVTimeoutError,
    dependency_to_osv_query,
    map_ecosystem_to_osv,
    normalize_version_for_osv,
)
from .scanner import (
    CVEScanner,
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
    extract_cve_id_from_osv,
    extract_cvss_score,
    extract_fixed_version_from_osv,
    extract_severity_from_osv,
    is_manifest_filename,
    map_cvss_to_severity,
    osv_vuln_to_finding,
    parse_cvss_v3_vector,
    parse_manifest_file,
    scan_directory,
    scan_manifest_file,
    scan_package,
    transform_osv_results_to_findings,
    transform_osv_vuln_to_finding,
)

__version__ = "0.1.0"

__all__ = [
    "CVEFinding",
    "CVEScanResult",
    "CVEScanner",
    "CVSS_CRITICAL_THRESHOLD",
    "CVSS_HIGH_THRESHOLD",
    "CVSS_MEDIUM_THRESHOLD",
    "Confidence",
    "ContractStatus",
    "DEFAULT_OSV_CACHE",
    "DeclaredDependency",
    "ECOSYSTEM_MAPPING",
    "Finding",
    "OSVCache",
    "OSVClient",
    "OSVClientError",
    "OSVConnectionError",
    "OSVHTTPError",
    "OSVResponseError",
    "OSVTimeoutError",
    "PackageScanResult",
    "ScanMetadata",
    "ScanStatus",
    "Severity",
    "SkippedFile",
    "compute_severity_counts",
    "dependency_to_osv_query",
    "evaluate_contract_status",
    "extract_cve_id_from_osv",
    "extract_cvss_score",
    "extract_fixed_version_from_osv",
    "extract_severity_from_osv",
    "is_manifest_filename",
    "map_cvss_to_severity",
    "map_ecosystem_to_osv",
    "normalize_version_for_osv",
    "osv_vuln_to_finding",
    "parse_cargo_toml",
    "parse_cvss_v3_vector",
    "parse_go_mod",
    "parse_manifest_file",
    "parse_package_json",
    "parse_package_lock_json",
    "parse_pipfile_lock",
    "parse_requirements_txt",
    "scan_directory",
    "scan_manifest_file",
    "scan_package",
    "transform_osv_results_to_findings",
    "transform_osv_vuln_to_finding",
]
