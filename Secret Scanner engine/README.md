# Secret & Static Analysis Scanner Engine

> A deterministic multi-scanner security engine combining rule-based secret detection, static code analysis, and dependency manifest inspection. Unified under a zero-translation contract with fail-closed gating, it blocks vulnerable packages from reaching production and protects marketplace listings.

[![Tests](https://img.shields.io/badge/tests-171%20passing-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

---

## Overview & Architecture

The **Secret & Static Analysis Scanner Engine** is designed to gate marketplace packages and repositories before deployment. It operates as a dual-engine security pipeline:

1. **Secrets Scanner Engine (`secrets_scanner`)**:
   - High-entropy and pattern-based detection for AWS access keys, GitHub tokens, Slack bot tokens, database connection URIs, private keys, and generic authorization bearer tokens.
   - History scanning over Git commits to detect leaked credentials buried in repository logs.
   - Allowlist suppression and automated secret redacting.

2. **Static Code & Manifest Analyzer (`static_analysis`)**:
   - Rule-based AST and regex security scanning across Python, JavaScript, TypeScript, and Shell scripts.
   - Detects dangerous execution patterns (`eval()`, `curl | sh`, unsanitized command injection, insecure deserialization, dangerous memory access).
   - Dependency manifest inspection pass for `package.json`, `requirements.txt`, `Pipfile.lock`, `Cargo.toml`, and `go.mod`.
   - Externalized malicious package and typosquat denylist check (`crossenv`, `fallflat`, etc.).

3. **Intake & Service Orchestrator (`service_orchestrator`)**:
   - Manages asynchronous package intake via file upload archives (`.zip`, `.tar.gz`) or direct GitHub repository URLs.
   - Enforces fail-closed gating: packages remain quarantined in `pending/` and listing status is set to `scan_failed` if any critical/high finding or parse error is discovered.
   - Promotes packages to `live/` object storage only upon a clean `passed` scan.

---

## Contract & Status Decision Logic

Both scanning engines return the identical **`PackageScanResult`** contract with zero translation layers:

| Field | Type | Description |
|---|---|---|
| `status` | `str` | `"passed"` \| `"failed"` \| `"error"` |
| `findings` | `List[Finding]` | Sanitized finding objects with rules, files, line numbers, and remediation hints |
| `severity_counts`| `Dict[str, int]` | Aggregated counts for `critical`, `high`, `medium`, `low` |
| `metadata` | `ScanMetadata` | Execution duration, files scanned, and files skipped |
| `suppressed_findings` | `List[SuppressedFinding]` | Findings suppressed via project allowlist |
| `error_message` | `Optional[str]` | Sanitized diagnostic error if an execution or syntax error occurred |

### Gating Decision Rules
- **`"failed"`**: Any finding carrying **Critical** or **High** severity **AND** **High** confidence.
- **`"passed"`**: Zero findings, or non-blocking findings (low/medium severity or low confidence). All findings remain visible to the seller.
- **`"error"`**: Unparseable manifest syntax errors (e.g. malformed `package.json`), scan budget timeouts, or unhandled exceptions. Treated identically to failed by the intake orchestrator.

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- Git (optional, for history auditing and repo cloning)

### Clone & Install
```bash
git clone https://github.com/avikengineer007/secret-scanner-engine.git
cd secret-scanner-engine

# Install package in editable development mode
pip install -e .
```

---

## CLI Usage

The repository provides three dedicated CLI commands (available as Python entry points and Windows batch scripts):

### 1. Secrets Scanner (`secrets-scan`)
Scan a target directory or repository for hardcoded credentials:
```bash
# Scan working tree
secrets-scan ./path/to/project

# Scan including full Git commit history
secrets-scan ./path/to/project --history

# Output machine-readable JSON
secrets-scan ./path/to/project --json
```

### 2. Static Analysis & Manifests (`static-scan`)
Scan for dangerous code patterns and malicious dependency typosquats:
```bash
# Full static code and dependency manifest scan
static-scan ./path/to/project

# Source code rules only (skip dependency manifest checks)
static-scan ./path/to/project --no-check-dependencies

# Output canonical PackageScanResult JSON
static-scan ./path/to/project --json

# Run with custom timeout budget (default: 30s)
static-scan ./path/to/project --timeout 15.0
```

### 3. Combined Production Preview (`scan-package`)
Preview the exact combined scan that `scan-service` runs in production:
```bash
# Using the dedicated combined script
scan-package ./path/to/project

# Or using the flag on static-scan
static-scan ./path/to/project --with-secrets-scan
```

### Exit Codes & `NO_COLOR`
All CLI commands follow strict exit code standards:
- `0`: Scan **passed** (no blocking findings)
- `1`: Scan **failed** (critical/high severity with high confidence detected)
- `2`: Scan **error** (malformed manifest syntax, budget timeout, or internal error)

> **`NO_COLOR` Compliance**: If the environment variable `NO_COLOR` is set (per [no-color.org](https://no-color.org/)) or output is redirected, ANSI color formatting is automatically disabled.

---

## Programmatic API

You can import and run either engine directly from Python, or merge them using the unified merge API:

```python
from secrets_scanner import scan_package as scan_secrets
from static_analysis import scan_package as scan_static, merge_package_results

target_dir = "./uploaded_package"

# 1. Run scanners
secrets_result = scan_secrets(target_dir)
static_result = scan_static(target_dir)

# 2. Merge results into a unified PackageScanResult
combined = merge_package_results(secrets_result, static_result)

print(f"Overall Status: {combined.status}")
print(f"Total Findings: {len(combined.findings)}")
print(f"Severity Breakdown: {combined.severity_counts}")

if combined.status != "passed":
    print(f"Package blocked: {combined.error_message or 'Security policy violations detected'}")
```

---

## End-to-End Seller Verification Demo

Run the integrated HTTP intake harness, background queue worker, and seller polling verification:

```bash
python demo_seller_verification.py
```

This live test executes 4 realistic seller lifecycle scenarios:
1. **Bad Secret Upload**: Verifies leaked AWS credentials land on `scan_failed` and never reach `live/`.
2. **Clean Package**: Verifies a clean package lands on `live` and is promoted to `live/` object storage.
3. **GitHub URL Intake**: Verifies repository cloning, commit SHA pinning, and history auditing.
4. **Dual-Scanner Execution**: Verifies concurrent detection of hardcoded Slack tokens and malicious npm packages, proving merged multi-scanner gating.

---

## Running the Test Suite

Execute the complete 171-test automated suite:

```bash
python -m unittest discover -s tests
```

---

## Repository Structure

```text
├── secrets_scanner/             # Core secrets detection engine
│   ├── orchestrator.py          # Secrets scanner runner
│   ├── rules.py                 # Secret patterns & entropy calculation
│   ├── contract.py              # Canonical PackageScanResult & merge logic
│   ├── intake.py                # Upload & GitHub repo intake boundary
│   ├── service_orchestrator.py  # Multi-scanner post-intake coordinator
│   └── cli.py                   # secrets-scan CLI implementation
├── static_analysis/             # Static code & manifest analysis engine
│   ├── scanner.py               # Static scanner runner & dispatcher
│   ├── rules.py                 # Dangerous AST & regex rules catalog
│   ├── manifests.py             # package.json, requirements.txt, Cargo, Go parsers
│   ├── data/                    # Externalized malicious package denylist
│   └── cli.py                   # static-scan & combined CLI implementation
├── tests/                       # Complete unit and integration test suite
│   ├── test_secrets.py          # Secrets scanner tests
│   ├── test_static_analysis.py  # Static analysis, manifest & CLI tests
│   ├── test_service_orchestrator.py
│   └── test_intake.py           # Intake & queue verification tests
├── demo_seller_verification.py  # E2E seller lifecycle demonstration tool
├── pyproject.toml               # Modern packaging metadata & console scripts
└── setup.py                     # Setuptools package configuration
```

---

## License

This project is licensed under the MIT License.
