"""Core static analysis engine orchestrator.

Enforces deterministic, rule-based scanning with language detection,
optional dependency manifest inspection, fail-closed error handling,
and strict budget controls imported directly from secrets_scanner.walker.
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from secrets_scanner.contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    compute_severity_counts,
    evaluate_contract_status,
)
from secrets_scanner.models import (
    Confidence,
    ScanStatus,
    Severity,
    SkippedFile,
)
from secrets_scanner.walker import (
    DEFAULT_IGNORED_DIRS,
    DEFAULT_MAX_DIRECTORY_DEPTH,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_MAX_TOTAL_FILES,
    ScanBudgetExceeded,
    read_text_file,
    walk_directory,
)

from .languages import DEFAULT_LANGUAGE_REGISTRY, LanguageRegistry
from .manifests import (
    inspect_manifest,
    is_manifest_file,
    load_denylist,
)
from .models import Finding, StaticScanResult
from .rules import Rule, get_default_rules
from .sanitizer import sanitize_text


class StaticAnalyzer:
    """Deterministic, rule-based static analysis engine.
    
    Guarantees:
      - Automatic language detection (extension + shebang line).
      - Strict budget enforcement reusing secrets_scanner.walker limits.
      - Dependency manifest supply-chain inspection (malicious packages, unpinned versions).
      - Fail-closed error handling on malformed manifests (routes to ScanStatus.ERROR).
      - Credential-scrubbed, bounded snippets on every finding.
    """

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        language_registry: Optional[LanguageRegistry] = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_total_files: int = DEFAULT_MAX_TOTAL_FILES,
        max_depth: int = DEFAULT_MAX_DIRECTORY_DEPTH,
        timeout_seconds: Optional[float] = 30.0,
        ignored_dirs: Optional[Set[str]] = None,
        follow_symlinks: bool = False,
        check_dependency_manifests: bool = True,
        checkDependencyManifests: Optional[bool] = None,
        denylist_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.rules = rules if rules is not None else get_default_rules()
        self.language_registry = language_registry or DEFAULT_LANGUAGE_REGISTRY
        self.max_file_size = max_file_size
        self.max_total_bytes = max_total_bytes
        self.max_total_files = max_total_files
        self.max_depth = max_depth
        self.timeout_seconds = timeout_seconds
        self.ignored_dirs = ignored_dirs if ignored_dirs is not None else set(DEFAULT_IGNORED_DIRS)
        self.follow_symlinks = follow_symlinks
        
        # Dependency manifest pass settings (supporting camelCase alias)
        if checkDependencyManifests is not None:
            self.check_dependency_manifests = checkDependencyManifests
        else:
            self.check_dependency_manifests = check_dependency_manifests
            
        self.denylist_path = denylist_path
        self.denylist = load_denylist(denylist_path)

    def detect_file_language(self, file_path: str, content: str) -> Optional[str]:
        """Detects language using file path extension, falling back to first line shebang."""
        first_line = ""
        if content:
            lines = content.splitlines()
            if lines:
                first_line = lines[0].strip()

        return self.language_registry.detect_language(file_path, first_line=first_line)

    def scan_content(
        self,
        file_path: str,
        content: str,
        language: Optional[str] = None
    ) -> List[Finding]:
        """Scans the text content of a single file against applicable language rules."""
        if not language:
            language = self.detect_file_language(file_path, content)

        if not language:
            return []

        findings: List[Finding] = []
        for rule in self.rules:
            if not rule.matches_language(language):
                continue

            matches = rule.matcher.match(content, file_path)
            for match in matches:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line_number=match.line_number,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        snippet=match.snippet,
                        description=rule.description,
                        language=language,
                        remediation_hint=rule.remediation_hint,
                        confidence=rule.confidence,
                    )
                )

        return findings

    def scan_directory(self, dir_path: str) -> StaticScanResult:
        """Scans a directory tree or single file for static analysis violations with fail-closed safety."""
        start_time = time.monotonic()

        # Fail-closed top-level validation
        try:
            target_path = Path(dir_path)
            if not target_path.exists():
                return StaticScanResult(
                    status=ScanStatus.FAILED,
                    success=False,
                    error_message=f"Directory does not exist: {target_path.name}"
                )

            # Support scanning a single target file directly
            if target_path.is_file():
                if target_path.stat().st_size > self.max_file_size:
                    return StaticScanResult(
                        status=ScanStatus.FAILED,
                        success=False,
                        error_message=f"File exceeds maximum allowed size ({self.max_file_size} bytes)",
                    )
                success, content, encoding, byte_count = read_text_file(str(target_path))
                if not success:
                    return StaticScanResult(
                        status=ScanStatus.FAILED,
                        success=False,
                        error_message=f"Unable to read file: {target_path.name}",
                    )

                findings: List[Finding] = []
                parse_error: Optional[str] = None

                if self.check_dependency_manifests and is_manifest_file(str(target_path)):
                    manifest_res = inspect_manifest(str(target_path), content, denylist=self.denylist)
                    findings.extend(manifest_res.findings)
                    parse_error = manifest_res.parse_error
                else:
                    lang = self.detect_file_language(str(target_path), content)
                    if lang:
                        findings.extend(self.scan_content(str(target_path), content, language=lang))

                if parse_error:
                    return StaticScanResult(
                        status=ScanStatus.ERROR,
                        success=False,
                        findings=findings,
                        files_scanned_count=1,
                        files_skipped=[],
                        error_message=f"Unable to parse dependency manifest '{target_path.name}': {parse_error}. Please verify file syntax and resubmit.",
                    )

                status = ScanStatus.FLAGGED if findings else ScanStatus.PASSED
                return StaticScanResult(
                    status=status,
                    success=True,
                    findings=findings,
                    files_scanned_count=1,
                    files_skipped=[],
                    error_message=None,
                )

            all_findings: List[Finding] = []
            files_scanned = 0
            skipped_files: List[SkippedFile] = []
            manifest_parse_errors: List[str] = []

            # Reuse secrets_scanner walker with identical budgets
            walker = walk_directory(
                str(target_path),
                max_file_size=self.max_file_size,
                max_total_bytes=self.max_total_bytes,
                max_total_files=self.max_total_files,
                max_depth=self.max_depth,
                timeout_seconds=self.timeout_seconds,
                start_time=start_time,
                ignored_dirs=self.ignored_dirs,
                follow_symlinks=self.follow_symlinks,
            )

            try:
                while True:
                    if self.timeout_seconds is not None and (time.monotonic() - start_time) > self.timeout_seconds:
                        raise ScanBudgetExceeded(
                            f"Scan wall-clock time limit exceeded ({self.timeout_seconds:.1f}s)"
                        )

                    file_path, content = next(walker)

                    # Pass 1: Dependency manifest inspection (if enabled)
                    if self.check_dependency_manifests and is_manifest_file(file_path):
                        files_scanned += 1
                        m_res = inspect_manifest(file_path, content, denylist=self.denylist)
                        all_findings.extend(m_res.findings)
                        if m_res.parse_error:
                            manifest_parse_errors.append(f"{Path(file_path).name}: {m_res.parse_error}")
                        continue

                    # Pass 2: Source code static analysis by language
                    language = self.detect_file_language(file_path, content)
                    if not language:
                        skipped_files.append(
                            SkippedFile(file_path=file_path, reason="unsupported_language")
                        )
                        continue

                    files_scanned += 1
                    file_findings = self.scan_content(file_path, content, language=language)
                    all_findings.extend(file_findings)

            except StopIteration as e:
                if e.value:
                    skipped_files.extend(e.value)

            # If any manifest failed to parse, route to ScanStatus.ERROR
            if manifest_parse_errors:
                combined_err = "; ".join(manifest_parse_errors)
                return StaticScanResult(
                    status=ScanStatus.ERROR,
                    success=False,
                    findings=all_findings,
                    files_scanned_count=files_scanned,
                    files_skipped=skipped_files,
                    error_message=f"Unable to parse dependency manifest: {combined_err}. Please verify file syntax and resubmit.",
                )

            status = ScanStatus.FLAGGED if all_findings else ScanStatus.PASSED
            return StaticScanResult(
                status=status,
                success=True,
                findings=all_findings,
                files_scanned_count=files_scanned,
                files_skipped=skipped_files,
                error_message=None,
            )

        except ScanBudgetExceeded as e:
            return StaticScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=f"ScanBudgetExceeded: {str(e)}",
            )
        except Exception as e:
            sanitized_error = f"{type(e).__name__}: {sanitize_text(str(e))}"
            return StaticScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=sanitized_error,
            )


def scan_directory(dir_path: str, **kwargs: Any) -> StaticScanResult:
    """Convenience helper to scan a directory using default StaticAnalyzer settings."""
    analyzer = StaticAnalyzer(**kwargs)
    return analyzer.scan_directory(dir_path)


def scan_package(
    target_dir: Optional[Union[str, Path]] = None,
    package_path: Optional[Union[str, Path]] = None,
    **kwargs: Any,
) -> PackageScanResult:
    """Drop-in scanner callable matching scan-service / secrets_scanner signature pattern.
    
    Accepts target_dir as first positional argument (or package_path for backward compatibility)
    and returns canonical PackageScanResult conforming to contract.py.
    """
    resolved_path = target_dir if target_dir is not None else package_path
    if resolved_path is None:
        raise ValueError("Must provide target_dir or package_path")

    allowed_kwargs = {
        "rules",
        "language_registry",
        "max_file_size",
        "max_total_bytes",
        "max_total_files",
        "max_depth",
        "timeout_seconds",
        "ignored_dirs",
        "follow_symlinks",
        "check_dependency_manifests",
        "checkDependencyManifests",
        "denylist_path",
    }
    filtered_kwargs = {k: v for k, v in kwargs.items() if k in allowed_kwargs}

    start_time = time.monotonic()
    analyzer = StaticAnalyzer(**filtered_kwargs)
    result = analyzer.scan_directory(str(resolved_path))
    duration = time.monotonic() - start_time
    return result.to_contract_result(duration_seconds=duration)
