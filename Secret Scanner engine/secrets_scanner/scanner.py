"""Core secrets scanning engine orchestrator."""

import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union
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
from .redactor import redact_line_snippet
from .entropy import extract_entropy_candidates, is_high_entropy_token
from .rules import get_default_rules, is_placeholder_value
from .allowlist import AllowlistConfig, load_allowlist_config
from .git_history import GitHistoryScanError, is_git_repository, stream_git_diff_entries
from .walker import (
    DEFAULT_MAX_DIRECTORY_DEPTH,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_MAX_TOTAL_FILES,
    ScanBudgetExceeded,
    walk_directory,
)


class SecretsScanner:
    """Deterministic, rule-based secrets scanning engine.
    
    Provides regex pattern matching and charset-aware Shannon entropy detection.
    Guarantees fail-closed error handling, placeholder suppression, zero leakage
    of raw secrets in findings, and auditable allowlist suppression.
    """
    
    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_total_files: int = DEFAULT_MAX_TOTAL_FILES,
        max_depth: int = DEFAULT_MAX_DIRECTORY_DEPTH,
        timeout_seconds: Optional[float] = 30.0,
        ignored_dirs: Optional[Set[str]] = None,
        follow_symlinks: bool = False,
        allowlist: Optional[List[Union[str, Pattern[str], Callable[[str, str], bool]]]] = None,
        allowlist_config: Optional[Union[str, Path, AllowlistConfig, Dict[str, Any], List[Dict[str, Any]]]] = None,
        suppress_placeholders: bool = True,
        scan_history: bool = False,
        max_commits: int = 500,
        **kwargs: Any,
    ):
        """Initializes the scanner with rules, configuration options, and allowlists.
        
        Args:
            rules: List of rules to apply (defaults to standard catalog).
            max_file_size: Maximum file size in bytes to scan per file (default 5MB).
            max_total_bytes: Maximum total decompressed bytes across the scan (default 100MB).
            max_total_files: Maximum number of files to process across scan (default 5,000).
            max_depth: Maximum directory nesting depth relative to scan root (default 20).
            timeout_seconds: Wall-clock timeout budget for total scan (default 30.0s).
            ignored_dirs: Set of directory names to skip (default .git, node_modules).
            follow_symlinks: Whether to follow symbolic links (default False).
            allowlist: Optional list of regex patterns, exact strings, or (token, file_path)->bool callables.
            allowlist_config: Optional file path, AllowlistConfig object, or dict/list for rule+path suppression.
            suppress_placeholders: Whether to ignore obvious placeholders (e.g. changeme, your_key_here).
            scan_history: Whether to inspect git commit history diffs if .git exists (default False).
            max_commits: Maximum commits to walk in git history (default 500).
        """
        self.rules = rules if rules is not None else get_default_rules()
        self.max_file_size = max_file_size
        self.max_total_bytes = max_total_bytes
        self.max_total_files = max_total_files
        self.max_depth = max_depth
        self.timeout_seconds = timeout_seconds
        self.ignored_dirs = ignored_dirs if ignored_dirs is not None else {".git", "node_modules"}
        self.follow_symlinks = follow_symlinks
        self.allowlist = allowlist or []
        self.allowlist_config: Optional[AllowlistConfig] = load_allowlist_config(allowlist_config)
        self.suppress_placeholders = suppress_placeholders
        
        if "scanHistory" in kwargs:
            scan_history = bool(kwargs["scanHistory"])
        self.scan_history = scan_history
        self.max_commits = max_commits
        self.suppressed_findings: List[SuppressedFinding] = []

        # Sort regex rules by precedence to ensure format-specific high confidence rules match before generic assignments
        def rule_precedence(r: Rule) -> int:
            if r.confidence == Confidence.HIGH:
                return 0
            if r.id in ("HARDCODED_PASSWORD", "GENERIC_API_KEY"):
                return 1
            if r.id == "GENERIC_SECRET_ASSIGNMENT":
                return 2
            return 3

        raw_regex_rules = [r for r in self.rules if r.rule_type == RuleType.REGEX and r.regex]
        raw_regex_rules.sort(key=rule_precedence)
        self.regex_rules = raw_regex_rules
        self.entropy_rules = [r for r in self.rules if r.rule_type == RuleType.ENTROPY]

    def is_allowed(self, token: str, file_path: str) -> bool:
        """Checks if a secret token is permitted by the allowlist or placeholder denylist."""
        if self.suppress_placeholders and is_placeholder_value(token):
            return True
            
        for item in self.allowlist:
            if isinstance(item, str):
                if item == token or item in token:
                    return True
            elif isinstance(item, re.Pattern):
                if item.search(token):
                    return True
            elif callable(item):
                try:
                    if item(token, file_path):
                        return True
                except Exception:
                    pass
        return False

    def scan_line(self, line: str, line_number: int, file_path: str) -> List[Finding]:
        """Scans a single line of text against active regex and entropy rules.
        
        Args:
            line: Content of the line.
            line_number: 1-indexed line number in source file.
            file_path: Relative or absolute path to the file.
            
        Returns:
            List of Finding objects detected on this line.
        """
        findings: List[Finding] = []
        matched_spans: List[Tuple[int, int]] = []
        
        # 1. Regex Pattern Matching (evaluated in priority order)
        for rule in self.regex_rules:
            if not rule.regex:
                continue
                
            for match in rule.regex.finditer(line):
                # If rule defines capture group 1 (e.g. secret assignment payload), use it
                if match.lastindex and match.lastindex >= 1 and match.group(1):
                    start, end = match.start(1), match.end(1)
                    raw_secret = match.group(1)
                else:
                    start, end = match.start(), match.end()
                    raw_secret = match.group(0)

                # Deduplication: check if candidate span overlaps with an already-matched higher-priority span
                if any(max(start, m_start) < min(end, m_end) for m_start, m_end in matched_spans):
                    continue

                # Check placeholder suppression
                if self.suppress_placeholders and is_placeholder_value(raw_secret):
                    matched_spans.append((start, end))
                    continue

                # Check custom inline allowlist
                if self.is_allowed(raw_secret, file_path):
                    matched_spans.append((start, end))
                    continue

                # Check allowlist config (rule ID + file path)
                if self.allowlist_config:
                    reason = self.allowlist_config.match(rule.id, file_path)
                    if reason:
                        snippet = redact_line_snippet(line, start, end)
                        self.suppressed_findings.append(
                            SuppressedFinding(
                                file_path=file_path,
                                line_number=line_number,
                                rule_id=rule.id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                confidence=rule.confidence,
                                reason=reason,
                                redacted_snippet=snippet,
                            )
                        )
                        matched_spans.append((start, end))
                        continue

                snippet = redact_line_snippet(line, start, end)
                matched_spans.append((start, end))
                
                findings.append(
                    Finding(
                        file_path=file_path,
                        line_number=line_number,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        redacted_snippet=snippet,
                        description=rule.description,
                    )
                )
                
        # 2. Shannon Entropy Scoring (active by default)
        for rule in self.entropy_rules:
            candidates = extract_entropy_candidates(line, min_length=rule.min_entropy_len)
            for token, start, end in candidates:
                # Avoid duplicate flagging if this span overlaps with any span already matched by regex
                if any(max(start, m_start) < min(end, m_end) for m_start, m_end in matched_spans):
                    continue

                # Check placeholder suppression
                if self.suppress_placeholders and is_placeholder_value(token):
                    matched_spans.append((start, end))
                    continue

                # Check custom inline allowlist
                if self.is_allowed(token, file_path):
                    matched_spans.append((start, end))
                    continue
                    
                is_high, score, charset = is_high_entropy_token(
                    token,
                    thresholds=rule.entropy_thresholds,
                    min_length=rule.min_entropy_len
                )
                
                if is_high:
                    # Dynamic confidence: score comfortably above threshold -> MEDIUM, borderline -> LOW
                    threshold = (rule.entropy_thresholds or {}).get(charset, 4.5)
                    confidence = Confidence.MEDIUM if score >= (threshold + 0.4) else Confidence.LOW

                    # Check allowlist config (rule ID + file path)
                    if self.allowlist_config:
                        reason = self.allowlist_config.match(rule.id, file_path)
                        if reason:
                            snippet = redact_line_snippet(line, start, end)
                            self.suppressed_findings.append(
                                SuppressedFinding(
                                    file_path=file_path,
                                    line_number=line_number,
                                    rule_id=rule.id,
                                    rule_name=rule.name,
                                    severity=rule.severity,
                                    confidence=confidence,
                                    reason=reason,
                                    redacted_snippet=snippet,
                                )
                            )
                            matched_spans.append((start, end))
                            continue

                    snippet = redact_line_snippet(line, start, end)
                    matched_spans.append((start, end))
                    
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line_number=line_number,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            confidence=confidence,
                            redacted_snippet=snippet,
                            description=f"{rule.description} ({charset} charset, entropy {score:.2f})",
                        )
                    )
                    
        return findings

    def scan_content(self, file_path: str, content: str) -> List[Finding]:
        """Scans the text content of a single file line-by-line.
        
        Args:
            file_path: Path of the file being scanned.
            content: Complete text content of the file.
            
        Returns:
            List of detected Finding objects.
        """
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_findings = self.scan_line(line, idx, file_path)
            findings.extend(line_findings)
        return findings

    def scan_directory(self, dir_path: str) -> ScanResult:
        """Scans an entire directory tree for secrets with fail-closed safety.
        
        Args:
            dir_path: Target directory path to scan.
            
        Returns:
            ScanResult containing status, findings, suppressed findings, and metadata.
        """
        start_time = time.monotonic()
        self.suppressed_findings = []
        
        # Fail-closed top-level handler
        try:
            target_path = Path(dir_path)
            if not target_path.exists():
                return ScanResult(
                    status=ScanStatus.FAILED,
                    success=False,
                    error_message=f"Directory does not exist: {target_path.name}"
                )
                
            if not target_path.is_dir():
                return ScanResult(
                    status=ScanStatus.FAILED,
                    success=False,
                    error_message=f"Target path is not a directory: {target_path.name}"
                )
            
            all_findings: List[Finding] = []
            files_scanned = 0
            
            walker = walk_directory(
                str(target_path),
                max_file_size=self.max_file_size,
                max_total_bytes=self.max_total_bytes,
                max_total_files=self.max_total_files,
                max_depth=self.max_depth,
                timeout_seconds=self.timeout_seconds,
                start_time=start_time,
                ignored_dirs=self.ignored_dirs,
                follow_symlinks=self.follow_symlinks
            )
            
            # Consume generator
            skipped_files: List[SkippedFile] = []
            try:
                while True:
                    # Timeout check during iteration
                    if self.timeout_seconds is not None and (time.monotonic() - start_time) > self.timeout_seconds:
                        raise ScanBudgetExceeded(f"Scan wall-clock time limit exceeded ({self.timeout_seconds:.1f}s)")
                        
                    file_path, content = next(walker)
                    files_scanned += 1
                    file_findings = self.scan_content(file_path, content)
                    all_findings.extend(file_findings)
            except StopIteration as e:
                # Generator return value is the skipped files list
                if e.value:
                    skipped_files = e.value

            # Optional Git History Scan Pass
            if self.scan_history and is_git_repository(str(target_path)):
                # Index working-tree findings for deduplication: (rule_id, rel_path, redacted_snippet)
                working_tree_index: Dict[Tuple[str, str, str], int] = {}
                for idx, f in enumerate(all_findings):
                    try:
                        rel_path = os.path.relpath(f.file_path, target_path).replace("\\", "/")
                    except ValueError:
                        rel_path = f.file_path.replace("\\", "/")
                    key = (f.rule_id, rel_path, f.redacted_snippet)
                    working_tree_index[key] = idx

                history_seen: Set[Tuple[str, str, str]] = set()

                for diff_line in stream_git_diff_entries(
                    str(target_path),
                    max_commits=self.max_commits,
                    max_total_bytes=self.max_total_bytes,
                    timeout_seconds=self.timeout_seconds,
                ):
                    line_findings = self.scan_line(
                        diff_line.content,
                        diff_line.line_number,
                        diff_line.file_path,
                    )
                    for hf in line_findings:
                        norm_path = diff_line.file_path.replace("\\", "/")
                        dedup_key = (hf.rule_id, norm_path, hf.redacted_snippet)

                        if dedup_key in working_tree_index:
                            # Finding appears in both working tree and history: report once, annotate with commit hash
                            wt_idx = working_tree_index[dedup_key]
                            existing = all_findings[wt_idx]
                            if not existing.commit_hash:
                                short_hash = diff_line.commit_hash[:8]
                                all_findings[wt_idx] = Finding(
                                    file_path=existing.file_path,
                                    line_number=existing.line_number,
                                    rule_id=existing.rule_id,
                                    rule_name=existing.rule_name,
                                    severity=existing.severity,
                                    confidence=existing.confidence,
                                    redacted_snippet=existing.redacted_snippet,
                                    description=f"{existing.description} (also found in git commit {short_hash})",
                                    commit_hash=diff_line.commit_hash,
                                )
                        else:
                            # Finding only in history (e.g. committed and removed in a later commit)
                            if dedup_key not in history_seen:
                                history_seen.add(dedup_key)
                                short_hash = diff_line.commit_hash[:8]
                                all_findings.append(
                                    Finding(
                                        file_path=diff_line.file_path,
                                        line_number=diff_line.line_number,
                                        rule_id=hf.rule_id,
                                        rule_name=hf.rule_name,
                                        severity=hf.severity,
                                        confidence=hf.confidence,
                                        redacted_snippet=hf.redacted_snippet,
                                        description=f"{hf.description} (historical commit {short_hash}, removed in later commits)",
                                        commit_hash=diff_line.commit_hash,
                                    )
                                )
                    
            status = ScanStatus.FLAGGED if all_findings else ScanStatus.PASSED
            return ScanResult(
                status=status,
                success=True,
                findings=all_findings,
                suppressed_findings=list(self.suppressed_findings),
                files_scanned_count=files_scanned,
                files_skipped=skipped_files,
                error_message=None
            )
            
        except GitHistoryScanError as e:
            # Fail closed on any git history error
            return ScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                suppressed_findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=f"GitHistoryScanError: {str(e)}"
            )
        except ScanBudgetExceeded as e:
            # Fail closed when scan limits are breached by untrusted input
            return ScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                suppressed_findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=f"ScanBudgetExceeded: {str(e)}"
            )
        except Exception as e:
            # Fail closed: never return success or PASSED when an unhandled error occurs
            sanitized_error = f"{type(e).__name__}: Operation failed safely"
            return ScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                suppressed_findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=sanitized_error
            )
