"""CVE & dependency vulnerability scanner.

Orchestrates manifest dependency extraction and batch vulnerability checks
against OSV.dev, converting results to the canonical PackageScanResult contract.
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Reusing manifest parsers and file detection directly from static_analysis - zero duplication
from static_analysis.manifests import (
    DeclaredDependency,
    is_manifest_file,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_requirements_txt,
)
from static_analysis.models import StaticScanResult
from static_analysis.sanitizer import scrub_credentials

# Reusing models and contract evaluation directly from secrets_scanner
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

from .cache import DEFAULT_OSV_CACHE, OSVCache
from .models import CVEFinding, CVEScanResult, Finding
from .osv_client import (
    OSVClient,
    OSVClientError,
    OSVConnectionError,
    OSVHTTPError,
    OSVResponseError,
    OSVTimeoutError,
    normalize_version_for_osv,
)

# Directory names to skip when walking directories
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "venv",
    ".venv",
    "env",
    ".env",
    "target",
    "dist",
    "build",
}

# Explicit CVSS score threshold mappings per security gating policy
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0


def parse_cvss_v3_vector(vector: str) -> Optional[float]:
    """Calculates CVSS 3.0/3.1 base score from a vector string.
    
    Formula per FIRST CVSS v3.1 specification:
    https://www.first.org/cvss/v3.1/specification-document
    """
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None

    metrics: Dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
    scope = metrics.get("S", "U")

    if scope == "U":
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics.get("PR", ""))
    else:
        pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(metrics.get("PR", ""))

    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("C", ""))
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("I", ""))
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("A", ""))

    if any(m is None for m in (av, ac, pr, ui, c, i, a)):
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0.0:
        return 0.0

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    import math
    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = min(10.0, math.ceil((min(impact + exploitability, 10.0)) * 10) / 10)
    else:
        base_score = min(10.0, math.ceil((min(1.08 * (impact + exploitability), 10.0)) * 10) / 10)

    return round(base_score, 1)


def extract_cvss_score(vuln: Dict[str, Any]) -> Optional[float]:
    """Extracts numeric CVSS base score from an OSV vulnerability record.
    
    Checks the 'severity' array for numeric scores or CVSS vector strings,
    as well as database_specific fields. Returns None if unscored.
    """
    sev_list = vuln.get("severity")
    if isinstance(sev_list, list):
        for item in sev_list:
            if not isinstance(item, dict):
                continue
            raw_score = item.get("score")
            # 1. Direct float/int
            if isinstance(raw_score, (int, float)):
                return float(raw_score)
            # 2. String score or vector
            if isinstance(raw_score, str):
                s = raw_score.strip()
                try:
                    return float(s)
                except ValueError:
                    pass
                if s.startswith("CVSS:3"):
                    parsed = parse_cvss_v3_vector(s)
                    if parsed is not None:
                        return parsed

    # 3. Check database_specific for cvss score
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        for key in ("cvss_score", "cvss", "score", "base_score"):
            val = db_specific.get(key)
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str):
                try:
                    return float(val.strip())
                except ValueError:
                    pass

    return None


def map_cvss_to_severity(score: Optional[float]) -> Tuple[Severity, bool]:
    """Maps CVSS score to Severity enum using explicit threshold mapping.
    
    Documented Threshold Mapping:
      - CVSS >= 9.0 -> Severity.CRITICAL
      - CVSS >= 7.0 -> Severity.HIGH
      - CVSS >= 4.0 -> Severity.MEDIUM
      - CVSS < 4.0  -> Severity.LOW
      - No score (None) -> Severity.MEDIUM (unscored)
      
    Returns:
        (severity, is_scored)
    """
    if score is None:
        return Severity.MEDIUM, False

    if score >= CVSS_CRITICAL_THRESHOLD:
        return Severity.CRITICAL, True
    if score >= CVSS_HIGH_THRESHOLD:
        return Severity.HIGH, True
    if score >= CVSS_MEDIUM_THRESHOLD:
        return Severity.MEDIUM, True
    return Severity.LOW, True


def extract_severity_from_osv(vuln: Dict[str, Any]) -> Severity:
    """Extracts finding severity from OSV vulnerability record."""
    score = extract_cvss_score(vuln)
    sev, _ = map_cvss_to_severity(score)
    return sev


def extract_cve_id_from_osv(vuln: Dict[str, Any]) -> Optional[str]:
    """Extracts a CVE identifier (e.g., CVE-2023-12345) from aliases or ID."""
    vuln_id = vuln.get("id", "")
    if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
        return vuln_id

    aliases = vuln.get("aliases", [])
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                return alias
    return None


def extract_fixed_version_from_osv(vuln: Dict[str, Any], pkg_name: Optional[str] = None) -> Optional[str]:
    """Finds the fixed version from affected ranges in the OSV vulnerability record."""
    affected = vuln.get("affected", [])
    if not isinstance(affected, list):
        return None

    for entry in affected:
        if not isinstance(entry, dict):
            continue
        # If package name is provided and entry specifies package, verify match
        if pkg_name:
            pkg_info = entry.get("package")
            if isinstance(pkg_info, dict) and "name" in pkg_info:
                if str(pkg_info["name"]).strip().lower() != pkg_name.strip().lower():
                    continue

        ranges = entry.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for r in ranges:
            if not isinstance(r, dict):
                continue
            events = r.get("events", [])
            if not isinstance(events, list):
                continue
            for ev in events:
                if isinstance(ev, dict) and "fixed" in ev:
                    return str(ev["fixed"]).strip()

    # Fallback to loose search without package name filtering
    if pkg_name:
        return extract_fixed_version_from_osv(vuln, pkg_name=None)
    return None


def transform_osv_vuln_to_finding(
    dep: DeclaredDependency,
    vuln: Dict[str, Any],
) -> Finding:
    """Transforms a single OSV vulnerability record into a canonical Finding object.
    
    Fields:
      - rule_id: the OSV vulnerability ID (e.g. 'GHSA-xxxx-xxxx-xxxx' or 'CVE-2023-12345')
      - rule_name: a short human title from the OSV record's summary field
      - severity: explicit threshold mapping from CVSS score (>=9.0 -> CRITICAL,
        >=7.0 -> HIGH, >=4.0 -> MEDIUM, else LOW). Defaults to MEDIUM with
        '(Unscored severity - defaulted to MEDIUM)' noted in description if unscored.
      - confidence: HIGH for direct OSV database match
      - description: sanitized summary/details (scrubbed of embedded credentials/URLs)
      - remediation_hint: fixed version upgrade guidance or generic monitor hint
      - file_path / line_number: from originating DeclaredDependency
    """
    rule_id = str(vuln.get("id") or "UNKNOWN_VULN").strip()

    summary = vuln.get("summary")
    if summary and isinstance(summary, str) and summary.strip():
        rule_name = summary.strip()
    else:
        rule_name = f"Vulnerability in {dep.name}"

    cvss_score = extract_cvss_score(vuln)
    severity, is_scored = map_cvss_to_severity(cvss_score)

    raw_desc = vuln.get("details") or vuln.get("summary") or f"Known vulnerability in {dep.name}"
    clean_desc = scrub_credentials(str(raw_desc).strip())
    if not is_scored:
        clean_desc = f"{clean_desc} (Unscored severity - defaulted to MEDIUM)"

    fixed_version = extract_fixed_version_from_osv(vuln, dep.name)
    if fixed_version:
        remediation_hint = f"Upgrade {dep.name} to {fixed_version} or later."
    else:
        remediation_hint = f"No fixed version published yet — monitor {rule_id} for updates."

    snippet = f'"{dep.name}": "{dep.version_spec}"' if dep.ecosystem == "npm" else f"{dep.name} {dep.version_spec or ''}".strip()
    cve_id = extract_cve_id_from_osv(vuln)

    return Finding(
        file_path=dep.file_path,
        line_number=dep.line_number,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        confidence=Confidence.HIGH,
        description=clean_desc,
        package_name=dep.name,
        ecosystem=dep.ecosystem,
        version=dep.version_spec,
        cve_id=cve_id,
        osv_id=rule_id,
        aliases=list(vuln.get("aliases", [])) if isinstance(vuln.get("aliases"), list) else [],
        fixed_version=fixed_version,
        snippet=snippet,
        remediation_hint=remediation_hint,
    )


# Convenient alias
osv_vuln_to_finding = transform_osv_vuln_to_finding


def transform_osv_results_to_findings(
    paired_results: List[Tuple[DeclaredDependency, List[Dict[str, Any]]]],
) -> List[Finding]:
    """Flattens matched OSV vulnerabilities into a list of Finding objects.
    
    Produces one Finding per vulnerability (not one finding per dependency).
    """
    findings: List[Finding] = []
    for dep, vulns in paired_results:
        for vuln in vulns:
            if isinstance(vuln, dict):
                findings.append(transform_osv_vuln_to_finding(dep, vuln))
    return findings


def parse_manifest_file(file_path: str) -> Tuple[List[DeclaredDependency], Optional[str]]:
    """Dispatches a manifest file to its appropriate parser.
    
    Returns:
        (dependencies, None) on success, or ([], error_message) on syntax/parse error.
    """
    path = Path(file_path)
    filename = path.name.lower()

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as err:
        return [], f"Failed to read file {path.name}: {err}"

    err_tuple: Optional[Tuple[str, int]] = None
    deps: List[DeclaredDependency] = []

    if filename == "package.json":
        deps, err_tuple = parse_package_json(content, str(path))
    elif filename == "package-lock.json":
        deps, err_tuple = parse_package_lock_json(content, str(path))
    elif filename in ("requirements.txt", "requirements.in") or filename.startswith("requirements-") or filename.endswith(".requirements.txt"):
        deps, err_tuple = parse_requirements_txt(content, str(path))
    elif filename == "pipfile.lock":
        deps, err_tuple = parse_pipfile_lock(content, str(path))
    elif filename == "go.mod":
        deps, err_tuple = parse_go_mod(content, str(path))
    elif filename == "cargo.toml":
        deps, err_tuple = parse_cargo_toml(content, str(path))
    else:
        # Not a supported manifest file
        return [], None

    if err_tuple:
        msg, line = err_tuple
        return [], f"Syntax error at line {line}: {msg}"

    return deps, None

def is_manifest_filename(name_or_path: str) -> bool:
    """Checks whether the file path or name corresponds to a supported dependency manifest.
    
    Directly delegates to static_analysis.manifests.is_manifest_file to prevent logic drift.
    """
    return is_manifest_file(name_or_path)


class CVEScanner:
    """Orchestrator for dependency extraction, OSV querying, and vulnerability findings.
    
    Coordinates manifest parsing, result-level caching, OSV.dev batch queries,
    and finding transformation while enforcing explicit network availability policies.
    """

    def __init__(
        self,
        client: Optional[OSVClient] = None,
        cache: Optional[OSVCache] = None,
        fail_open_on_osv_unavailable: bool = False,
        check_cve: bool = True,
        timeout: float = 10.0,
        cache_ttl: Optional[float] = None,
        no_cache: bool = False,
        **kwargs: Any,
    ):
        self.client = client if client is not None else OSVClient(timeout=timeout)
        self.no_cache = no_cache
        if no_cache:
            self.cache = None
        else:
            self.cache = cache if cache is not None else DEFAULT_OSV_CACHE
        self.fail_open_on_osv_unavailable = fail_open_on_osv_unavailable
        self.check_cve = check_cve
        self.timeout = float(timeout)
        if cache_ttl is not None:
            self.cache_ttl = float(cache_ttl)
        elif self.cache is not None:
            self.cache_ttl = float(self.cache.default_ttl)
        else:
            self.cache_ttl = 3600.0

    def _query_dependencies_with_cache(
        self,
        dependencies: List[DeclaredDependency],
    ) -> List[Tuple[DeclaredDependency, List[Dict[str, Any]]]]:
        """Queries OSV for dependencies using result-level caching.
        
        Avoids duplicate network calls for identical (ecosystem, package_name, version)
        entries within the TTL window.
        """
        if not dependencies:
            return []

        results: List[Optional[List[Dict[str, Any]]]] = [None] * len(dependencies)
        # Group uncached dependencies by (ecosystem, name, version) to deduplicate network queries
        uncached_map: Dict[Tuple[str, str, Optional[str]], List[int]] = {}
        deps_to_query: List[DeclaredDependency] = []

        for idx, dep in enumerate(dependencies):
            clean_v = normalize_version_for_osv(dep.version_spec)
            cached_vulns = None
            if self.cache is not None:
                cached_vulns = self.cache.get(dep.ecosystem, dep.name, clean_v)
                if cached_vulns is None and dep.version_spec and dep.version_spec != clean_v:
                    cached_vulns = self.cache.get(dep.ecosystem, dep.name, dep.version_spec)

            if cached_vulns is not None:
                results[idx] = cached_vulns
            else:
                key = (dep.ecosystem.strip().lower(), dep.name.strip().lower(), clean_v)
                if key not in uncached_map:
                    uncached_map[key] = []
                    deps_to_query.append(dep)
                uncached_map[key].append(idx)

        if deps_to_query:
            batch_pairs = self.client.query_dependencies(deps_to_query)
            for q_dep, vulns in batch_pairs:
                clean_v = normalize_version_for_osv(q_dep.version_spec)
                key = (q_dep.ecosystem.strip().lower(), q_dep.name.strip().lower(), clean_v)
                if self.cache is not None:
                    self.cache.set(q_dep.ecosystem, q_dep.name, clean_v, vulns, ttl=self.cache_ttl)
                    if q_dep.version_spec and q_dep.version_spec != clean_v:
                        self.cache.set(q_dep.ecosystem, q_dep.name, q_dep.version_spec, vulns, ttl=self.cache_ttl)

                for idx in uncached_map.get(key, []):
                    results[idx] = [dict(v) for v in vulns]

        return [
            (dep, results[idx] if results[idx] is not None else [])
            for idx, dep in enumerate(dependencies)
        ]

    def _query_and_build_result(
        self,
        dependencies: List[DeclaredDependency],
        files_scanned_count: int,
        files_skipped: List[SkippedFile],
    ) -> CVEScanResult:
        """Constructs CVEScanResult with explicit network failure policy enforcement."""
        if not dependencies:
            return CVEScanResult(
                status=ScanStatus.PASSED,
                success=True,
                findings=[],
                files_scanned_count=files_scanned_count,
                files_skipped=files_skipped,
                error_message=None,
            )

        try:
            paired_results = self._query_dependencies_with_cache(dependencies)
        except (OSVClientError, Exception) as err:
            if self.fail_open_on_osv_unavailable:
                return CVEScanResult(
                    status=ScanStatus.PASSED,
                    success=True,
                    findings=[],
                    files_scanned_count=files_scanned_count,
                    files_skipped=files_skipped,
                    error_message=f"CVE check skipped due to OSV.dev unavailability: {err}",
                )
            else:
                return CVEScanResult(
                    status=ScanStatus.ERROR,
                    success=False,
                    findings=[],
                    files_scanned_count=files_scanned_count,
                    files_skipped=files_skipped,
                    error_message=f"OSV.dev API unavailable (network failure / timeout): {err}",
                )

        findings = transform_osv_results_to_findings(paired_results)
        status = ScanStatus.FLAGGED if findings else ScanStatus.PASSED

        return CVEScanResult(
            status=status,
            success=True,
            findings=findings,
            files_scanned_count=files_scanned_count,
            files_skipped=files_skipped,
            error_message=None,
        )

    def scan_manifest_file(self, file_path: str) -> CVEScanResult:
        """Scans a single manifest file for CVE vulnerabilities."""
        if not self.check_cve:
            return CVEScanResult(
                status=ScanStatus.PASSED,
                success=True,
                findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=None,
            )

        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return CVEScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=f"Manifest file does not exist: {file_path}",
            )

        deps, parse_err = parse_manifest_file(str(p))
        if parse_err:
            return CVEScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                files_scanned_count=1,
                files_skipped=[],
                error_message=f"Manifest parse error in {p.name}: {parse_err}",
            )

        return self._query_and_build_result(
            dependencies=deps,
            files_scanned_count=1,
            files_skipped=[],
        )

    def scan_directory(self, target_dir: str) -> CVEScanResult:
        """Scans all manifest files in target_dir using unified batch querying."""
        if not self.check_cve:
            return CVEScanResult(
                status=ScanStatus.PASSED,
                success=True,
                findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=None,
            )

        root_path = Path(target_dir)
        if not root_path.exists() or not root_path.is_dir():
            return CVEScanResult(
                status=ScanStatus.FAILED,
                success=False,
                findings=[],
                files_scanned_count=0,
                files_skipped=[],
                error_message=f"Target directory does not exist: {target_dir}",
            )

        manifest_files: List[Path] = []
        skipped: List[SkippedFile] = []

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            for f in sorted(files):
                file_p = Path(root) / f
                if is_manifest_file(str(file_p)):
                    manifest_files.append(file_p)

        all_dependencies: List[DeclaredDependency] = []
        files_scanned = 0

        for mfile in manifest_files:
            deps, parse_err = parse_manifest_file(str(mfile))
            files_scanned += 1
            if parse_err:
                return CVEScanResult(
                    status=ScanStatus.FAILED,
                    success=False,
                    findings=[],
                    files_scanned_count=files_scanned,
                    files_skipped=skipped,
                    error_message=f"Manifest parse error in {mfile.name}: {parse_err}",
                )
            all_dependencies.extend(deps)

        return self._query_and_build_result(
            dependencies=all_dependencies,
            files_scanned_count=files_scanned,
            files_skipped=skipped,
        )

    def scan_package(self, target_path: str) -> PackageScanResult:
        """Scans a file or directory and returns a canonical PackageScanResult."""
        start_time = time.perf_counter()
        p = Path(target_path)

        if p.is_file():
            res = self.scan_manifest_file(str(p))
        else:
            res = self.scan_directory(str(p))

        duration = time.perf_counter() - start_time
        return res.to_contract_result(duration_seconds=duration)


def scan_manifest_file(
    file_path: str,
    client: Optional[OSVClient] = None,
    cache: Optional[OSVCache] = None,
    fail_open_on_osv_unavailable: bool = False,
    check_cve: bool = True,
    timeout: float = 10.0,
    cache_ttl: Optional[float] = None,
    no_cache: bool = False,
    **kwargs: Any,
) -> CVEScanResult:
    """Scans a single manifest file for CVE vulnerabilities."""
    scanner = CVEScanner(
        client=client,
        cache=cache,
        fail_open_on_osv_unavailable=fail_open_on_osv_unavailable,
        check_cve=check_cve,
        timeout=timeout,
        cache_ttl=cache_ttl,
        no_cache=no_cache,
        **kwargs,
    )
    return scanner.scan_manifest_file(file_path)


def scan_directory(
    target_dir: str,
    client: Optional[OSVClient] = None,
    cache: Optional[OSVCache] = None,
    fail_open_on_osv_unavailable: bool = False,
    check_cve: bool = True,
    timeout: float = 10.0,
    cache_ttl: Optional[float] = None,
    no_cache: bool = False,
    **kwargs: Any,
) -> CVEScanResult:
    """Scans all manifest files in target_dir using unified dependency batching."""
    scanner = CVEScanner(
        client=client,
        cache=cache,
        fail_open_on_osv_unavailable=fail_open_on_osv_unavailable,
        check_cve=check_cve,
        timeout=timeout,
        cache_ttl=cache_ttl,
        no_cache=no_cache,
        **kwargs,
    )
    return scanner.scan_directory(target_dir)


def scan_package(
    target_dir: Optional[Union[str, Path]] = None,
    target_path: Optional[Union[str, Path]] = None,
    client: Optional[OSVClient] = None,
    cache: Optional[OSVCache] = None,
    fail_open_on_osv_unavailable: bool = False,
    check_cve: bool = True,
    timeout: float = 10.0,
    cache_ttl: Optional[float] = None,
    no_cache: bool = False,
    **kwargs: Any,
) -> PackageScanResult:
    """Canonical entry point conforming to scan-service interface.
    
    Identical signature pattern to secrets_scanner.scan_package and static_analysis.scan_package.
    Accepts target_dir as primary positional argument and returns canonical PackageScanResult.
    """
    resolved_path = target_dir if target_dir is not None else target_path
    if resolved_path is None:
        raise ValueError("Must provide target_dir or target_path")

    scanner = CVEScanner(
        client=client,
        cache=cache,
        fail_open_on_osv_unavailable=fail_open_on_osv_unavailable,
        check_cve=check_cve,
        timeout=timeout,
        cache_ttl=cache_ttl,
        no_cache=no_cache,
        **kwargs,
    )
    return scanner.scan_package(resolved_path)
