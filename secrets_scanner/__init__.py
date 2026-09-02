"""Secrets Scanning Engine.

A deterministic, rule-based secrets scanning engine for auditing source code packages.
"""

from .models import (
    Confidence,
    Finding,
    Rule,
    RuleType,
    ScanResult,
    ScanStatus,
    Severity,
    SkippedFile,
    SuppressedFinding,
)
from .redactor import (
    redact_line_snippet,
    redact_secret,
)
from .entropy import (
    calculate_shannon_entropy,
    detect_charset,
    is_high_entropy_token,
)
from .rules import (
    DEFAULT_RULES,
    get_default_rules,
    is_placeholder_value,
    PLACEHOLDER_DENYLIST,
)
from .allowlist import (
    AllowlistConfig,
    AllowlistEntry,
    load_allowlist_config,
)
from .git_history import (
    GitHistoryScanError,
    is_git_repository,
    stream_git_diff_entries,
)
from .walker import (
    ScanBudgetExceeded,
    is_binary_content,
    read_text_file,
    walk_directory,
)
from .scanner import (
    SecretsScanner,
)
from .extractor import (
    ArchiveSecurityError,
    safe_extract_archive,
)

from .contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    compute_severity_counts,
    evaluate_contract_status,
    merge_package_results,
)
from .orchestrator import (
    scan_package,
)
from .intake import (
    CloneError,
    CredentialError,
    EncryptedEnvelope,
    EnvelopeCipher,
    GitHubAppCredentialStore,
    GitHubAppGrant,
    IntakeError,
    IntakePipeline,
    IntakeSource,
    ListingStatus,
    ListingVersion,
    LocalRootKeyKMSProvider,
    KMSProvider,
    UploadRecord,
    normalize_repo_url,
    safe_clone_github_repo,
    sanitize_text,
)
from .service_orchestrator import (
    DEFAULT_SCANNERS,
    InMemoryObjectStorage,
    InMemoryPostgresListingRepository,
    ListingRepository,
    ObjectStorageClient,
    ScanOutcome,
    merge_scan_results,
    process_upload,
)
from .job_queue import (
    AsyncIntakeResponse,
    IntakeGateway,
    JobStatus,
    PostgresJobQueue,
    ScanJob,
    ScanJobWorker,
    reap_timed_out_jobs,
)
from .server import (
    ListingStatusService,
    ScanServiceApp,
    ScanServiceHTTPHandler,
    collapse_seller_status,
    create_scan_service_app,
)

__all__ = [
    "SecretsScanner",
    "scan_package",
    "PackageScanResult",
    "ScanMetadata",
    "ContractStatus",
    "compute_severity_counts",
    "evaluate_contract_status",
    "Finding",
    "SuppressedFinding",
    "Confidence",
    "Rule",
    "RuleType",
    "ScanResult",
    "ScanStatus",
    "Severity",
    "SkippedFile",
    "ScanBudgetExceeded",
    "ArchiveSecurityError",
    "safe_extract_archive",
    "redact_secret",
    "redact_line_snippet",
    "calculate_shannon_entropy",
    "detect_charset",
    "is_high_entropy_token",
    "is_placeholder_value",
    "PLACEHOLDER_DENYLIST",
    "DEFAULT_RULES",
    "get_default_rules",
    "AllowlistConfig",
    "AllowlistEntry",
    "load_allowlist_config",
    "GitHistoryScanError",
    "is_git_repository",
    "stream_git_diff_entries",
    "is_binary_content",
    "read_text_file",
    "walk_directory",
    "IntakeSource",
    "ListingStatus",
    "ListingVersion",
    "UploadRecord",
    "GitHubAppGrant",
    "GitHubAppCredentialStore",
    "IntakePipeline",
    "safe_clone_github_repo",
    "EnvelopeCipher",
    "LocalRootKeyKMSProvider",
    "KMSProvider",
    "EncryptedEnvelope",
    "normalize_repo_url",
    "sanitize_text",
    "IntakeError",
    "CloneError",
    "CredentialError",
    "process_upload",
    "ScanOutcome",
    "ObjectStorageClient",
    "ListingRepository",
    "InMemoryObjectStorage",
    "InMemoryPostgresListingRepository",
    "DEFAULT_SCANNERS",
    "merge_scan_results",
    "merge_package_results",
    "JobStatus",
    "ScanJob",
    "PostgresJobQueue",
    "ScanJobWorker",
    "IntakeGateway",
    "AsyncIntakeResponse",
    "reap_timed_out_jobs",
    "collapse_seller_status",
    "ListingStatusService",
    "ScanServiceHTTPHandler",
    "create_scan_service_app",
    "ScanServiceApp",
]




