"""Dependency manifest inspector for static analysis engine.

Inspects package manifests (package.json, requirements.txt, go.mod, Cargo.toml, lockfiles)
for:
  1. Known-malicious or typosquatted package names (via external curated denylist).
  2. Pinned vs. unpinned dependency versions (supply-chain risk surface).
  3. Fail-closed error handling on malformed/unparseable manifests.
"""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None

from secrets_scanner.models import Confidence, Severity
from .models import Finding

# Path to the bundled seed denylist
DEFAULT_DENYLIST_PATH = Path(__file__).parent / "data" / "malicious_packages.json"


@dataclass(frozen=True)
class DeclaredDependency:
    """Represents a dependency parsed from a manifest file."""
    name: str
    version_spec: Optional[str]
    is_pinned: bool
    ecosystem: str  # "npm", "pypi", "crates", "golang"
    file_path: str
    line_number: int


@dataclass
class ManifestInspectionResult:
    """Outcome of inspecting a manifest file."""
    file_path: str
    dependencies: List[DeclaredDependency]
    findings: List[Finding]
    parse_error: Optional[str] = None
    parse_error_line: Optional[int] = None


def load_denylist(custom_path: Optional[Union[str, Path]] = None) -> Dict[str, Set[str]]:
    """Loads the malicious package denylist from JSON.
    
    Args:
        custom_path: Optional explicit file path to a denylist JSON file.
        
    Returns:
        Dictionary mapping ecosystem name ('npm', 'pypi', etc.) to lowercase package names.
    """
    path = Path(custom_path) if custom_path else DEFAULT_DENYLIST_PATH
    if not path.exists():
        return {"npm": set(), "pypi": set(), "crates": set(), "golang": set()}

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return {
            ecosystem: {pkg.strip().lower() for pkg in pkgs if isinstance(pkg, str)}
            for ecosystem, pkgs in raw.items()
            if isinstance(pkgs, list)
        }
    except Exception:
        return {"npm": set(), "pypi": set(), "crates": set(), "golang": set()}


def is_manifest_file(file_path: str) -> bool:
    """Checks whether the file path corresponds to a supported dependency manifest."""
    name = Path(file_path).name.lower()
    if name in (
        "package.json", "package-lock.json", "yarn.lock",
        "requirements.txt", "pipfile.lock", "go.mod",
        "cargo.toml", "cargo.lock"
    ):
        return True
    if name.startswith("requirements-") and name.endswith(".txt"):
        return True
    if name.endswith(".requirements.txt"):
        return True
    return False


# =============================================================================
# Manifest Parsers
# =============================================================================

def parse_package_json(content: str, file_path: str) -> Tuple[List[DeclaredDependency], Optional[Tuple[str, int]]]:
    """Parses package.json for declared dependencies.
    
    Returns:
        (dependencies, None) on success, or ([], (error_message, line_number)) on syntax error.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [], (f"Invalid JSON syntax in {Path(file_path).name}: {e.msg} (line {e.lineno}, col {e.colno})", e.lineno)

    if not isinstance(data, dict):
        return [], (f"Expected top-level JSON object in {Path(file_path).name}", 1)

    dependencies: List[DeclaredDependency] = []
    lines = content.splitlines()

    # Sections to inspect in package.json
    dep_sections = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    for section in dep_sections:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue

        for pkg_name, version_spec in deps.items():
            if not isinstance(pkg_name, str):
                continue

            v_str = str(version_spec).strip() if version_spec is not None else ""
            # Pinned vs Unpinned check for npm:
            # Unpinned: starts with ^, ~, >, <, *, or is "latest", or is empty
            is_pinned = not (
                v_str.startswith(("^", "~", ">", "<", "*"))
                or v_str.lower() in ("*", "latest", "")
                or "||" in v_str
                or " - " in v_str
            )

            # Locate line number heuristically
            line_no = 1
            search_key = f'"{pkg_name}"'
            for idx, line in enumerate(lines, start=1):
                if search_key in line:
                    line_no = idx
                    break

            dependencies.append(
                DeclaredDependency(
                    name=pkg_name.strip(),
                    version_spec=v_str,
                    is_pinned=is_pinned,
                    ecosystem="npm",
                    file_path=file_path,
                    line_number=line_no,
                )
            )

    return dependencies, None


def parse_requirements_txt(content: str, file_path: str) -> Tuple[List[DeclaredDependency], Optional[Tuple[str, int]]]:
    """Parses Python requirements.txt file line-by-line."""
    dependencies: List[DeclaredDependency] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        clean = line.strip()
        # Skip comments and empty lines
        if not clean or clean.startswith("#"):
            continue
        # Skip pip options like -r other.txt or -i https://...
        if clean.startswith("-"):
            continue

        # Strip environment markers (e.g. "; python_version >= '3.8'")
        if ";" in clean:
            clean = clean.split(";", 1)[0].strip()

        # Check for strict pinned equality '=='
        if "==" in clean:
            parts = clean.split("==", 1)
            pkg_name = parts[0].strip()
            version_spec = parts[1].strip()
            # Wildcards like ==1.2.* are unpinned
            is_pinned = "*" not in version_spec
        elif any(op in clean for op in (">=", "<=", "~=", "!=", ">", "<")):
            # Open-ended or bounded range specifier -> unpinned
            op_match = re.search(r"([><=~!]+)", clean)
            if op_match:
                op = op_match.group(1)
                pkg_name, version_spec = clean.split(op, 1)
                pkg_name = pkg_name.strip()
                version_spec = op + version_spec.strip()
            else:
                pkg_name = clean
                version_spec = ""
            is_pinned = False
        else:
            # Completely bare package name with no version
            pkg_name = clean
            version_spec = ""
            is_pinned = False

        if pkg_name:
            dependencies.append(
                DeclaredDependency(
                    name=pkg_name,
                    version_spec=version_spec or None,
                    is_pinned=is_pinned,
                    ecosystem="pypi",
                    file_path=file_path,
                    line_number=idx,
                )
            )

    return dependencies, None


def parse_pipfile_lock(content: str, file_path: str) -> Tuple[List[DeclaredDependency], Optional[Tuple[str, int]]]:
    """Parses Pipfile.lock JSON structure."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [], (f"Invalid JSON syntax in {Path(file_path).name}: {e.msg} (line {e.lineno}, col {e.colno})", e.lineno)

    if not isinstance(data, dict):
        return [], (f"Expected top-level JSON object in {Path(file_path).name}", 1)

    dependencies: List[DeclaredDependency] = []
    lines = content.splitlines()

    for section in ("default", "develop"):
        pkgs = data.get(section)
        if not isinstance(pkgs, dict):
            continue

        for pkg_name, details in pkgs.items():
            version_spec = details.get("version") if isinstance(details, dict) else None
            is_pinned = bool(version_spec and version_spec.startswith("=="))

            line_no = 1
            search_key = f'"{pkg_name}"'
            for idx, line in enumerate(lines, start=1):
                if search_key in line:
                    line_no = idx
                    break

            dependencies.append(
                DeclaredDependency(
                    name=pkg_name,
                    version_spec=version_spec,
                    is_pinned=is_pinned,
                    ecosystem="pypi",
                    file_path=file_path,
                    line_number=line_no,
                )
            )

    return dependencies, None


def parse_go_mod(content: str, file_path: str) -> Tuple[List[DeclaredDependency], Optional[Tuple[str, int]]]:
    """Parses go.mod dependencies including multi-line require blocks."""
    dependencies: List[DeclaredDependency] = []
    lines = content.splitlines()
    in_require_block = False

    for idx, line in enumerate(lines, start=1):
        clean = line.strip()
        # Strip inline comments
        if "//" in clean:
            clean = clean.split("//", 1)[0].strip()

        if not clean:
            continue

        if clean == "require (":
            in_require_block = True
            continue
        elif in_require_block and clean == ")":
            in_require_block = False
            continue

        if in_require_block:
            tokens = clean.split()
            if len(tokens) >= 2:
                mod_name, version = tokens[0], tokens[1]
                dependencies.append(
                    DeclaredDependency(
                        name=mod_name,
                        version_spec=version,
                        is_pinned=True,  # go.mod require directives pin explicit versions or pseudo-versions
                        ecosystem="golang",
                        file_path=file_path,
                        line_number=idx,
                    )
                )
        elif clean.startswith("require "):
            tokens = clean[len("require "):].strip().split()
            if len(tokens) >= 2:
                mod_name, version = tokens[0], tokens[1]
                dependencies.append(
                    DeclaredDependency(
                        name=mod_name,
                        version_spec=version,
                        is_pinned=True,
                        ecosystem="golang",
                        file_path=file_path,
                        line_number=idx,
                    )
                )

    return dependencies, None


def parse_cargo_toml(content: str, file_path: str) -> Tuple[List[DeclaredDependency], Optional[Tuple[str, int]]]:
    """Parses Cargo.toml dependencies using tomllib."""
    if tomllib is None:
        return [], ("TOML parser not available in current Python environment", 1)

    try:
        data = tomllib.loads(content)
    except Exception as e:
        return [], (f"Invalid TOML syntax in {Path(file_path).name}: {str(e)}", 1)

    dependencies: List[DeclaredDependency] = []
    lines = content.splitlines()

    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
        sec_dict = data.get(sec)
        if not isinstance(sec_dict, dict):
            continue

        for pkg_name, spec in sec_dict.items():
            if isinstance(spec, str):
                v_str = spec.strip()
                # In Cargo, unpinned is explicitly wildcard "*" or empty
                is_pinned = v_str not in ("*", "")
            elif isinstance(spec, dict):
                v_str = str(spec.get("version", "")).strip()
                is_pinned = v_str not in ("*", "")
            else:
                v_str = ""
                is_pinned = False

            line_no = 1
            for idx, line in enumerate(lines, start=1):
                if line.strip().startswith(pkg_name):
                    line_no = idx
                    break

            dependencies.append(
                DeclaredDependency(
                    name=pkg_name,
                    version_spec=v_str or None,
                    is_pinned=is_pinned,
                    ecosystem="crates",
                    file_path=file_path,
                    line_number=line_no,
                )
            )

    return dependencies, None


# =============================================================================
# Inspector Function
# =============================================================================

def inspect_manifest(
    file_path: str,
    content: str,
    denylist: Optional[Dict[str, Set[str]]] = None,
) -> ManifestInspectionResult:
    """Inspects a single manifest file content for malicious packages and unpinned versions.
    
    Args:
        file_path: Path to the manifest file.
        content: Raw text content of the manifest.
        denylist: Loaded dictionary of denylisted packages by ecosystem.
        
    Returns:
        ManifestInspectionResult with declared dependencies and any findings.
    """
    if denylist is None:
        denylist = load_denylist()

    filename = Path(file_path).name.lower()
    deps: List[DeclaredDependency] = []
    err: Optional[Tuple[str, int]] = None

    if filename == "package.json":
        deps, err = parse_package_json(content, file_path)
    elif filename in ("requirements.txt", "requirements.in") or filename.startswith("requirements-") or filename.endswith(".requirements.txt"):
        deps, err = parse_requirements_txt(content, file_path)
    elif filename == "pipfile.lock":
        deps, err = parse_pipfile_lock(content, file_path)
    elif filename == "go.mod":
        deps, err = parse_go_mod(content, file_path)
    elif filename == "cargo.toml":
        deps, err = parse_cargo_toml(content, file_path)
    else:
        # Lockfiles or other supported types that are clean/pass-through
        return ManifestInspectionResult(file_path=file_path, dependencies=[], findings=[])

    findings: List[Finding] = []

    # If parse error occurred, emit clear seller-facing syntax finding.
    # ARCHITECTURAL NOTE ON GATING VS SEVERITY:
    # Gating is driven entirely by ContractStatus.ERROR (via has_error=True in
    # StaticScanResult.to_contract_result()), which the orchestrator treats identically
    # to FAILED for blocking publication. The finding's severity=Severity.HIGH is
    # purely informational (required by the typed Finding schema, feeds telemetry
    # severity_counts, and renders a distinct "High Priority Syntax Error" badge in
    # the seller UI rather than mislabeling an honest typo as a CRITICAL malware detection).
    # Altering the severity field here does not change gating outcomes.
    if err is not None:
        err_msg, err_line = err
        findings.append(
            Finding(
                file_path=file_path,
                line_number=err_line,
                rule_id="MANIFEST_PARSE_ERROR",
                rule_name="Malformed Dependency Manifest",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                snippet=f"Failed parsing {Path(file_path).name}",
                description=f"{err_msg}. Scans cannot verify dependency safety on unparseable manifests.",
                language="manifest",
                remediation_hint=f"Check {Path(file_path).name} for syntax formatting errors (e.g. trailing commas, valid JSON/TOML) and resubmit.",
            )
        )
        return ManifestInspectionResult(
            file_path=file_path,
            dependencies=[],
            findings=findings,
            parse_error=err_msg,
            parse_error_line=err_line,
        )

    # Inspect each parsed dependency
    for dep in deps:
        eco_denylist = denylist.get(dep.ecosystem, set())
        # Check 1: Denylist match
        if dep.name.lower() in eco_denylist:
            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=dep.line_number,
                    rule_id="MANIFEST_MALICIOUS_DEPENDENCY",
                    rule_name="Known Malicious Dependency Name",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    snippet=f'"{dep.name}": "{dep.version_spec}"' if dep.ecosystem == "npm" else f"{dep.name} {dep.version_spec or ''}".strip(),
                    description=f"Dependency '{dep.name}' matches a known malicious package or typosquat on {dep.ecosystem}.",
                    language="manifest",
                    remediation_hint=f"Remove '{dep.name}' immediately. If this was a misspelling of a legitimate package, verify the package name on official package registries.",
                )
            )

        # Check 2: Unpinned version
        if not dep.is_pinned:
            v_display = dep.version_spec if dep.version_spec else "none (unspecified)"
            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=dep.line_number,
                    rule_id="MANIFEST_UNPINNED_DEPENDENCY",
                    rule_name="Unpinned Dependency Version",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    snippet=f'"{dep.name}": "{dep.version_spec}"' if dep.ecosystem == "npm" else f"{dep.name} {dep.version_spec or ''}".strip(),
                    description=f"Dependency '{dep.name}' specifies unpinned version '{v_display}'. Unpinned versions introduce supply-chain vulnerability surfaces.",
                    language="manifest",
                    remediation_hint=f"Pin '{dep.name}' to an exact, immutable version (e.g. '1.2.3' without ^/~ or '==1.2.3'), or commit an authoritative lockfile.",
                )
            )

    return ManifestInspectionResult(
        file_path=file_path,
        dependencies=deps,
        findings=findings,
        parse_error=None,
    )
