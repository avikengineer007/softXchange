"""Unit tests for the CVE / vulnerability-checking module (cve_check).

Validates:
  1. Strict reuse of models and parser functions from secrets_scanner and static_analysis.
  2. OSV.dev batch API client behavior under mocked HTTP:
     - Successful batch response with findings
     - Successful batch response with zero findings
     - Request timeout producing OSVTimeoutError
     - Non-200 HTTP error producing OSVHTTPError with status code & body
     - Connection error producing OSVConnectionError
     - Malformed JSON response producing OSVResponseError
     - Retry with exponential backoff on transient 5xx errors
     - Optional authentication header / API key injection
  3. Ecosystem mapping and version specifier normalization.
  4. End-to-end scanner orchestration:
     - Manifest dependency extraction via imported static_analysis parsers
     - Finding generation with CVE / GHSA attribution and severity mapping
     - Fail-closed gating on client network errors (never silently treated as clean)
"""

import io
import json
import os
import socket
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from unittest.mock import MagicMock, patch

# 1. Verify direct imports from secrets_scanner - strict reuse discipline
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

# 2. Verify direct imports from static_analysis.manifests
from static_analysis.manifests import (
    DeclaredDependency,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_package_lock_json,
    parse_pipfile_lock,
    parse_requirements_txt,
)

# 3. Imports from cve_check
from cve_check.cache import DEFAULT_OSV_CACHE, OSVCache
from cve_check.models import CVEFinding, CVEScanResult, Finding
from cve_check.osv_client import (
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
from cve_check.scanner import (
    CVEScanner,
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
    extract_cve_id_from_osv,
    extract_cvss_score,
    extract_fixed_version_from_osv,
    extract_severity_from_osv,
    map_cvss_to_severity,
    osv_vuln_to_finding,
    parse_cvss_v3_vector,
    scan_directory,
    scan_manifest_file,
    scan_package,
    transform_osv_results_to_findings,
    transform_osv_vuln_to_finding,
)


class MockHTTPResponse:
    """Helper to simulate urllib.request.urlopen context manager response."""

    def __init__(self, status: int, data: Union[str, bytes, Dict[str, Any]], headers: Optional[Dict[str, str]] = None):
        self.status = status
        if isinstance(data, (dict, list)):
            self._body = json.dumps(data).encode("utf-8")
        elif isinstance(data, str):
            self._body = data.encode("utf-8")
        else:
            self._body = data
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestCVECheckModelReuse(unittest.TestCase):
    """Verifies architectural reuse requirements: no parallel definitions."""

    def test_reused_enums_and_contract_classes(self):
        # Severity, Confidence, ScanStatus, SkippedFile identity
        self.assertIs(Severity.CRITICAL.value, "critical")
        self.assertIs(Confidence.HIGH.value, "high")
        self.assertIs(ScanStatus.PASSED.value, "passed")

        # Contract types
        meta = ScanMetadata(duration_seconds=1.23, files_scanned=2, files_skipped=0, scan_history_ran=False)
        self.assertEqual(meta.files_scanned, 2)

        res = PackageScanResult(status=ContractStatus.PASSED)
        self.assertEqual(res.status, "passed")

    def test_reused_manifest_parsers_and_dependency_model(self):
        dep = DeclaredDependency(
            name="express",
            version_spec="4.18.2",
            is_pinned=True,
            ecosystem="npm",
            file_path="package.json",
            line_number=10,
        )
        self.assertEqual(dep.name, "express")
        self.assertEqual(dep.ecosystem, "npm")

        # Validate imported parser functions exist and are callable
        self.assertTrue(callable(parse_package_json))
        self.assertTrue(callable(parse_package_lock_json))
        self.assertTrue(callable(parse_requirements_txt))
        self.assertTrue(callable(parse_pipfile_lock))
        self.assertTrue(callable(parse_go_mod))
        self.assertTrue(callable(parse_cargo_toml))


class TestOSVClient(unittest.TestCase):
    """Tests OSV.dev batch API client using mocked HTTP layer."""

    def setUp(self):
        self.client = OSVClient(timeout=5.0, max_retries=1, backoff_factor=0.01)

    # -------------------------------------------------------------------------
    # 1. Successful batch response with findings
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_successful_batch_response_with_findings(self, mock_urlopen):
        # Simulate OSV batch response with 1 vuln for lodash and 1 vuln for jinja2
        mock_response_data = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-p6mc-m468-83gw",
                            "summary": "Prototype Pollution in lodash",
                            "aliases": ["CVE-2020-8203"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "ranges": [
                                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}
                                    ]
                                }
                            ],
                        }
                    ]
                },
                {
                    "vulns": [
                        {
                            "id": "GHSA-g3rq-g295-4j35",
                            "summary": "Sandbox Escape in Jinja2",
                            "aliases": ["CVE-2019-10906"],
                            "database_specific": {"severity": "CRITICAL"},
                            "affected": [
                                {
                                    "ranges": [
                                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}
                                    ]
                                }
                            ],
                        }
                    ]
                },
            ]
        }
        mock_urlopen.return_value = MockHTTPResponse(200, mock_response_data)

        deps = [
            DeclaredDependency("lodash", "4.17.15", True, "npm", "package.json", 12),
            DeclaredDependency("jinja2", "==2.10.0", True, "pypi", "requirements.txt", 5),
        ]

        paired = self.client.query_dependencies(deps)

        self.assertEqual(len(paired), 2)
        # Check lodash findings
        dep0, vulns0 = paired[0]
        self.assertEqual(dep0.name, "lodash")
        self.assertEqual(len(vulns0), 1)
        self.assertEqual(vulns0[0]["id"], "GHSA-p6mc-m468-83gw")
        self.assertEqual(vulns0[0]["aliases"], ["CVE-2020-8203"])

        # Check jinja2 findings
        dep1, vulns1 = paired[1]
        self.assertEqual(dep1.name, "jinja2")
        self.assertEqual(len(vulns1), 1)
        self.assertEqual(vulns1[0]["id"], "GHSA-g3rq-g295-4j35")

        # Verify request structure
        mock_urlopen.assert_called_once()
        call_req = mock_urlopen.call_args[0][0]
        self.assertEqual(call_req.get_method(), "POST")
        self.assertIn("/querybatch", call_req.full_url)
        payload = json.loads(call_req.data.decode("utf-8"))
        self.assertEqual(len(payload["queries"]), 2)
        self.assertEqual(payload["queries"][0], {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15"})
        self.assertEqual(payload["queries"][1], {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.10.0"})

    # -------------------------------------------------------------------------
    # 2. Successful batch response with NO findings
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_successful_batch_response_no_findings(self, mock_urlopen):
        mock_response_data = {
            "results": [
                {},  # clean package 1
                {"vulns": []},  # clean package 2
            ]
        }
        mock_urlopen.return_value = MockHTTPResponse(200, mock_response_data)

        deps = [
            DeclaredDependency("safe-pkg-1", "1.0.0", True, "npm", "package.json", 1),
            DeclaredDependency("safe-pkg-2", "2.0.0", True, "pypi", "requirements.txt", 2),
        ]

        paired = self.client.query_dependencies(deps)
        self.assertEqual(len(paired), 2)
        self.assertEqual(paired[0][1], [])
        self.assertEqual(paired[1][1], [])

    # -------------------------------------------------------------------------
    # 3. Timeout error produces distinct OSVTimeoutError
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_timeout_raises_osv_timeout_error(self, mock_urlopen):
        # Simulate socket.timeout
        mock_urlopen.side_effect = socket.timeout("timed out while reading socket")

        queries = [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.25.1"}]

        with self.assertRaises(OSVTimeoutError) as ctx:
            self.client.query_batch(queries)

        self.assertIsInstance(ctx.exception, OSVTimeoutError)
        self.assertIsInstance(ctx.exception, OSVClientError)
        self.assertEqual(ctx.exception.timeout, 5.0)
        self.assertIn("timed out", str(ctx.exception).lower())

    @patch("urllib.request.urlopen")
    def test_url_error_timeout_raises_osv_timeout_error(self, mock_urlopen):
        # Simulate urllib.error.URLError with timeout reason
        mock_urlopen.side_effect = urllib.error.URLError(socket.timeout("Operation timed out"))

        queries = [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.25.1"}]

        with self.assertRaises(OSVTimeoutError) as ctx:
            self.client.query_batch(queries)

        self.assertIsInstance(ctx.exception, OSVTimeoutError)

    # -------------------------------------------------------------------------
    # 4. Non-200 HTTP error produces distinct OSVHTTPError with status code
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_non_200_http_error(self, mock_urlopen):
        # Simulate HTTP 400 Bad Request
        fp = io.BytesIO(b'{"error": "Invalid ecosystem"}')
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.osv.dev/v1/querybatch",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=fp,
        )

        queries = [{"package": {"name": "foo", "ecosystem": "invalid"}, "version": "1.0"}]

        with self.assertRaises(OSVHTTPError) as ctx:
            self.client.query_batch(queries)

        self.assertIsInstance(ctx.exception, OSVHTTPError)
        self.assertIsInstance(ctx.exception, OSVClientError)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Invalid ecosystem", ctx.exception.response_body)

    # -------------------------------------------------------------------------
    # 5. Connection failure produces distinct OSVConnectionError
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_connection_error_raises_osv_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused [Errno 111]")

        queries = [{"package": {"name": "foo", "ecosystem": "npm"}, "version": "1.0"}]

        with self.assertRaises(OSVConnectionError) as ctx:
            self.client.query_batch(queries)

        self.assertIsInstance(ctx.exception, OSVConnectionError)
        self.assertIsInstance(ctx.exception, OSVClientError)
        self.assertIn("Connection refused", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 6. Malformed JSON response produces OSVResponseError
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_malformed_json_raises_osv_response_error(self, mock_urlopen):
        mock_urlopen.return_value = MockHTTPResponse(200, "<html>Bad Gateway</html>")

        queries = [{"package": {"name": "foo", "ecosystem": "npm"}, "version": "1.0"}]

        with self.assertRaises(OSVResponseError) as ctx:
            self.client.query_batch(queries)

        self.assertIsInstance(ctx.exception, OSVResponseError)

    # -------------------------------------------------------------------------
    # 7. Transient 5xx retry with backoff
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_retry_on_transient_503(self, mock_urlopen):
        # First call fails with 503, second call succeeds
        fp = io.BytesIO(b'{"error": "Temporary Unavailable"}')
        err_503 = urllib.error.HTTPError(
            url="https://api.osv.dev/v1/querybatch",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=fp,
        )
        success_resp = MockHTTPResponse(200, {"results": [{}]})
        mock_urlopen.side_effect = [err_503, success_resp]

        queries = [{"package": {"name": "express", "ecosystem": "npm"}, "version": "4.18.2"}]
        results = self.client.query_batch(queries)

        self.assertEqual(len(results), 1)
        self.assertEqual(mock_urlopen.call_count, 2)

    # -------------------------------------------------------------------------
    # 8. Authentication header / API key injection
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_auth_header_injection(self, mock_urlopen):
        mock_urlopen.return_value = MockHTTPResponse(200, {"results": []})
        auth_client = OSVClient(api_key="my-secret-osv-key")

        queries = [{"package": {"name": "foo", "ecosystem": "npm"}}]
        auth_client.query_batch(queries)

        call_req = mock_urlopen.call_args[0][0]
        self.assertIn("Authorization", call_req.headers)
        self.assertEqual(call_req.headers["Authorization"], "Bearer my-secret-osv-key")


class TestEcosystemMappingAndNormalization(unittest.TestCase):
    """Tests ecosystem conversions and version normalization."""

    def test_ecosystem_mapping(self):
        self.assertEqual(map_ecosystem_to_osv("npm"), "npm")
        self.assertEqual(map_ecosystem_to_osv("pypi"), "PyPI")
        self.assertEqual(map_ecosystem_to_osv("crates"), "crates.io")
        self.assertEqual(map_ecosystem_to_osv("golang"), "Go")
        self.assertEqual(map_ecosystem_to_osv("go"), "Go")
        self.assertEqual(map_ecosystem_to_osv("rust"), "crates.io")

    def test_version_normalization(self):
        self.assertEqual(normalize_version_for_osv("==1.2.3"), "1.2.3")
        self.assertEqual(normalize_version_for_osv("=4.5.6"), "4.5.6")
        self.assertEqual(normalize_version_for_osv("^18.2.0"), "18.2.0")
        self.assertEqual(normalize_version_for_osv("~2.1.0"), "2.1.0")
        self.assertEqual(normalize_version_for_osv("3.0.0"), "3.0.0")
        self.assertIsNone(normalize_version_for_osv(None))
        self.assertIsNone(normalize_version_for_osv(""))

    def test_dependency_to_osv_query(self):
        dep = DeclaredDependency("serde", "==1.0.150", True, "crates", "Cargo.toml", 8)
        query = dependency_to_osv_query(dep)
        self.assertEqual(query["package"]["name"], "serde")
        self.assertEqual(query["package"]["ecosystem"], "crates.io")
        self.assertEqual(query["version"], "1.0.150")


class TestCVEScanner(unittest.TestCase):
    """Tests end-to-end scanner execution over manifest files."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch.object(OSVClient, "query_dependencies")
    def test_scan_manifest_file_with_vulnerabilities(self, mock_query):
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text(json.dumps({
            "dependencies": {
                "lodash": "4.17.15"
            }
        }), encoding="utf-8")

        mock_query.return_value = [
            (
                DeclaredDependency("lodash", "4.17.15", True, "npm", str(manifest_path), 3),
                [
                    {
                        "id": "GHSA-p6mc-m468-83gw",
                        "summary": "Prototype Pollution in lodash",
                        "aliases": ["CVE-2020-8203"],
                        "severity": [{"type": "CVSS_V3", "score": 7.5}],
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {"ranges": [{"events": [{"fixed": "4.17.19"}]}]}
                        ],
                    }
                ]
            )
        ]

        result = scan_manifest_file(str(manifest_path))

        self.assertEqual(result.status, ScanStatus.FLAGGED)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 1)

        f = result.findings[0]
        self.assertEqual(f.package_name, "lodash")
        self.assertEqual(f.cve_id, "CVE-2020-8203")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.confidence, Confidence.HIGH)
        self.assertEqual(f.fixed_version, "4.17.19")
        self.assertIn("Upgrade lodash to 4.17.19", f.remediation_hint)

        # Test canonical contract conversion
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "failed")
        self.assertEqual(contract_res.severity_counts["high"], 1)
        self.assertIsNone(contract_res.error_message)

    @patch.object(OSVClient, "query_dependencies")
    def test_scan_manifest_file_clean(self, mock_query):
        manifest_path = self.test_dir / "requirements.txt"
        manifest_path.write_text("requests==2.31.0\nurllib3==2.0.7\n", encoding="utf-8")

        mock_query.return_value = [
            (DeclaredDependency("requests", "==2.31.0", True, "pypi", str(manifest_path), 1), []),
            (DeclaredDependency("urllib3", "==2.0.7", True, "pypi", str(manifest_path), 2), []),
        ]

        result = scan_manifest_file(str(manifest_path))

        self.assertEqual(result.status, ScanStatus.PASSED)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 0)

        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "passed")
        self.assertEqual(contract_res.severity_counts["critical"], 0)
        self.assertEqual(contract_res.severity_counts["high"], 0)

    @patch.object(OSVClient, "query_dependencies")
    def test_fail_closed_on_network_failure(self, mock_query):
        """CRITICAL: Verifies network failures are NEVER silently treated as clean."""
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text(json.dumps({"dependencies": {"express": "4.18.2"}}), encoding="utf-8")

        # Simulate timeout error from client
        mock_query.side_effect = OSVTimeoutError("OSV batch query timed out after 10.0s", timeout=10.0)

        result = scan_manifest_file(str(manifest_path))

        self.assertEqual(result.status, ScanStatus.ERROR)
        self.assertFalse(result.success)
        self.assertIn("OSV.dev API unavailable", result.error_message)
        self.assertIn("timed out", result.error_message)

        # Fail-closed contract status must evaluate to "error", NOT "passed"
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "error")
        self.assertIsNotNone(contract_res.error_message)

    def test_manifest_syntax_error_fails_closed(self):
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text("{ unquoted_broken_json :::: ", encoding="utf-8")

        result = scan_manifest_file(str(manifest_path))
        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertFalse(result.success)
        self.assertIn("Manifest parse error", result.error_message)

        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "error")


class TestOSVToFindingTransformation(unittest.TestCase):
    """Tests transformation of raw OSV responses into Finding objects."""

    def setUp(self):
        self.dep = DeclaredDependency(
            name="lodash",
            version_spec="4.17.15",
            is_pinned=True,
            ecosystem="npm",
            file_path="package.json",
            line_number=24,
        )

    def test_single_scored_vulnerability(self):
        """Tests a single dependency with a scored vulnerability mapping to Critical/High."""
        vuln_crit = {
            "id": "GHSA-35jh-r3h4-6jhm",
            "summary": "Command Injection in lodash",
            "details": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection.",
            "aliases": ["CVE-2021-23337"],
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}  # 7.2 HIGH
            ],
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ]
                }
            ]
        }

        finding = transform_osv_vuln_to_finding(self.dep, vuln_crit)

        # 1. rule_id: OSV vulnerability ID
        self.assertEqual(finding.rule_id, "GHSA-35jh-r3h4-6jhm")
        # 2. rule_name: short human title from summary
        self.assertEqual(finding.rule_name, "Command Injection in lodash")
        # 3. severity: mapped from CVSS score
        self.assertEqual(finding.severity, Severity.HIGH)
        # 4. confidence: HIGH
        self.assertEqual(finding.confidence, Confidence.HIGH)
        # 5. description: sanitized details/summary
        self.assertIn("vulnerable to Command Injection", finding.description)
        # 6. remediation_hint: fixed version from affected ranges
        self.assertEqual(finding.remediation_hint, "Upgrade lodash to 4.17.21 or later.")
        self.assertEqual(finding.fixed_version, "4.17.21")
        # 7. file_path / line_number from originating dependency
        self.assertEqual(finding.file_path, "package.json")
        self.assertEqual(finding.line_number, 24)

    def test_cvss_threshold_mapping(self):
        """Tests explicit CVSS threshold mapping: >=9.0 Critical, >=7.0 High, >=4.0 Medium, <4.0 Low."""
        # Critical
        self.assertEqual(map_cvss_to_severity(9.8)[0], Severity.CRITICAL)
        self.assertEqual(map_cvss_to_severity(9.0)[0], Severity.CRITICAL)
        # High
        self.assertEqual(map_cvss_to_severity(8.9)[0], Severity.HIGH)
        self.assertEqual(map_cvss_to_severity(7.0)[0], Severity.HIGH)
        # Medium
        self.assertEqual(map_cvss_to_severity(6.9)[0], Severity.MEDIUM)
        self.assertEqual(map_cvss_to_severity(4.0)[0], Severity.MEDIUM)
        # Low
        self.assertEqual(map_cvss_to_severity(3.9)[0], Severity.LOW)
        self.assertEqual(map_cvss_to_severity(1.0)[0], Severity.LOW)

    def test_multiple_vulnerabilities_on_single_dependency(self):
        """Tests producing one Finding per vulnerability (not one finding per dependency)."""
        vulns = [
            {
                "id": "GHSA-1",
                "summary": "Vulnerability 1",
                "severity": [{"type": "CVSS_V3", "score": 9.5}],
                "affected": [{"ranges": [{"events": [{"fixed": "4.17.16"}]}]}],
            },
            {
                "id": "GHSA-2",
                "summary": "Vulnerability 2",
                "severity": [{"type": "CVSS_V3", "score": 7.5}],
                "affected": [{"ranges": [{"events": [{"fixed": "4.17.18"}]}]}],
            },
            {
                "id": "GHSA-3",
                "summary": "Vulnerability 3",
                "severity": [{"type": "CVSS_V3", "score": 4.5}],
                "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
            },
        ]

        paired = [(self.dep, vulns)]
        findings = transform_osv_results_to_findings(paired)

        self.assertEqual(len(findings), 3)
        self.assertEqual([f.rule_id for f in findings], ["GHSA-1", "GHSA-2", "GHSA-3"])
        self.assertEqual([f.rule_name for f in findings], ["Vulnerability 1", "Vulnerability 2", "Vulnerability 3"])
        self.assertEqual([f.severity for f in findings], [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM])
        for f in findings:
            self.assertEqual(f.package_name, "lodash")
            self.assertEqual(f.file_path, "package.json")
            self.assertEqual(f.line_number, 24)

    def test_unscored_advisory_defaults_to_medium(self):
        """Tests that an unscored advisory defaults to MEDIUM with note in description."""
        unscored_vuln = {
            "id": "CVE-2023-99999",
            "summary": "Unrated vulnerability in lodash",
            "details": "Details about unrated bug without CVSS score.",
            # No severity field or CVSS score
        }

        finding = transform_osv_vuln_to_finding(self.dep, unscored_vuln)

        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("Unscored severity - defaulted to MEDIUM", finding.description)
        self.assertEqual(finding.rule_id, "CVE-2023-99999")
        self.assertEqual(finding.rule_name, "Unrated vulnerability in lodash")

    def test_vulnerability_with_no_fixed_version(self):
        """Tests that vulnerabilities without a fixed version use the generic remediation hint."""
        unfixed_vuln = {
            "id": "GHSA-unfixed-001",
            "summary": "Zero-day with no fix yet",
            "affected": [
                {
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}
                        # No "fixed" event
                    ]
                }
            ]
        }

        finding = transform_osv_vuln_to_finding(self.dep, unfixed_vuln)

        self.assertIsNone(finding.fixed_version)
        self.assertEqual(
            finding.remediation_hint,
            "No fixed version published yet — monitor GHSA-unfixed-001 for updates.",
        )

    def test_sanitization_in_description(self):
        """Tests that description runs through credential sanitization."""
        leak_vuln = {
            "id": "GHSA-leak-001",
            "summary": "Advisory with embedded sensitive URL",
            "details": "Exploit against https://admin:supersecret@cluster.internal/v1 using api_key: 'abcdef1234567890'.",
        }

        finding = transform_osv_vuln_to_finding(self.dep, leak_vuln)

        self.assertNotIn("supersecret", finding.description)
        self.assertIn("https://[REDACTED]@cluster.internal/v1", finding.description)
        self.assertIn('api_key="[REDACTED]"', finding.description)


class TestCVECheckCLI(unittest.TestCase):
    """Tests cve-scan CLI interface and exit codes."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("cve_check.cli.scan_package")
    def test_cli_exit_code_passed(self, mock_scan):
        mock_scan.return_value = PackageScanResult(status="passed")
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text("{}", encoding="utf-8")

        from cve_check.cli import main
        code = main([str(manifest_path)])
        self.assertEqual(code, 0)

    @patch("cve_check.cli.scan_package")
    def test_cli_exit_code_failed(self, mock_scan):
        mock_scan.return_value = PackageScanResult(
            status="failed",
            findings=[
                CVEFinding(
                    file_path=str(self.test_dir / "package.json"),
                    line_number=2,
                    rule_id="CVE-2021-1234",
                    rule_name="Vulnerable Dependency: bad-pkg",
                    severity=Severity.HIGH,
                    description="Critical flaw",
                    package_name="bad-pkg",
                    ecosystem="npm",
                )
            ],
            severity_counts={"high": 1, "critical": 0, "medium": 0, "low": 0},
        )
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text("{}", encoding="utf-8")

        from cve_check.cli import main
        code = main([str(manifest_path)])
        self.assertEqual(code, 1)

    @patch("cve_check.cli.scan_package")
    def test_cli_json_mode(self, mock_scan):
        mock_scan.return_value = PackageScanResult(status="passed")
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text("{}", encoding="utf-8")

        from cve_check.cli import main
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            code = main([str(manifest_path), "--json"])
            self.assertEqual(code, 0)
            data = json.loads(mock_stdout.getvalue())
            self.assertEqual(data["status"], "passed")
            self.assertIn("findings", data)
            self.assertIn("severity_counts", data)

    def test_cli_nonexistent_path(self):
        from cve_check.cli import main
        code = main(["/nonexistent/path/package.json"])
        self.assertEqual(code, 2)

    @patch("cve_check.cli.scan_package")
    def test_cli_exit_code_error(self, mock_scan):
        """Confirms CLI returns exit code 2 when status is 'error'."""
        mock_scan.return_value = PackageScanResult(
            status="error",
            error_message="OSV API unavailable (network timeout)",
        )
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text("{}", encoding="utf-8")

        from cve_check.cli import main
        code = main([str(manifest_path)])
        self.assertEqual(code, 2)

    @patch("cve_check.cli.scan_package")
    def test_cli_flags_forwarded_to_scan_package(self, mock_scan):
        """Confirms --fail-open and --no-cache are correctly forwarded to scan_package."""
        mock_scan.return_value = PackageScanResult(status="passed")
        manifest_path = self.test_dir / "package.json"
        manifest_path.write_text("{}", encoding="utf-8")

        from cve_check.cli import main
        code = main([str(manifest_path), "--fail-open", "--no-cache"])
        self.assertEqual(code, 0)
        self.assertTrue(mock_scan.called)
        call_kwargs = mock_scan.call_args[1]
        self.assertTrue(call_kwargs.get("fail_open_on_osv_unavailable"))
        self.assertTrue(call_kwargs.get("no_cache"))

    def test_cli_human_report_severity_grouping(self):
        """Confirms human report renders severity-grouped headers matching secrets-scan & static-scan."""
        from cve_check.cli import Colors, format_cve_human_report

        f_crit = CVEFinding(
            file_path="package.json",
            line_number=5,
            rule_id="CVE-2023-9999",
            rule_name="Critical RCE in dep",
            severity=Severity.CRITICAL,
            description="Remote code execution",
            package_name="dep",
            ecosystem="npm",
        )
        f_med = CVEFinding(
            file_path="package.json",
            line_number=8,
            rule_id="CVE-2023-1111",
            rule_name="Medium ReDoS in regex",
            severity=Severity.MEDIUM,
            description="Regex denial of service",
            package_name="regex",
            ecosystem="npm",
            fixed_version="1.2.3",
            remediation_hint="Upgrade regex to 1.2.3",
        )
        result = PackageScanResult(
            status="failed",
            findings=[f_med, f_crit],
            severity_counts={"critical": 1, "high": 0, "medium": 1, "low": 0},
            metadata=ScanMetadata(0.01, 1, 0, False),
        )

        colors = Colors(enabled=False)
        report = format_cve_human_report(result, "package.json", colors)

        self.assertIn("--- CRITICAL FINDINGS (1) ---", report)
        self.assertIn("--- MEDIUM FINDINGS (1) ---", report)
        crit_idx = report.index("--- CRITICAL FINDINGS")
        med_idx = report.index("--- MEDIUM FINDINGS")
        self.assertLess(crit_idx, med_idx)
        self.assertIn("Fixed in   : 1.2.3", report)
        self.assertIn("Remediation: Upgrade regex to 1.2.3", report)

    def test_cli_no_color_environment(self):
        """Confirms NO_COLOR disables terminal escape sequences."""
        from secrets_scanner.cli import should_use_color
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(should_use_color())


class TestCVEScannerOrchestrator(unittest.TestCase):
    """Tests CVEScanner orchestrator pass, caching, and network availability policies."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch.object(OSVClient, "query_dependencies")
    def test_full_scan_directory_with_findings(self, mock_query):
        """Tests end-to-end directory scan with multiple manifests producing findings."""
        # Create package.json and requirements.txt
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}), encoding="utf-8")
        req_txt = self.test_dir / "requirements.txt"
        req_txt.write_text("requests==2.25.1\n", encoding="utf-8")

        mock_query.return_value = [
            (
                DeclaredDependency("lodash", "4.17.15", True, "npm", str(pkg_json), 3),
                [
                    {
                        "id": "GHSA-p6mc-m468-83gw",
                        "summary": "Prototype Pollution in lodash",
                        "aliases": ["CVE-2020-8203"],
                        "severity": [{"type": "CVSS_V3", "score": 7.5}],
                        "affected": [{"ranges": [{"events": [{"fixed": "4.17.19"}]}]}],
                    }
                ],
            ),
            (
                DeclaredDependency("requests", "==2.25.1", True, "pypi", str(req_txt), 1),
                [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "Unintended leak of Proxy-Authorization header in requests",
                        "aliases": ["CVE-2023-32681"],
                        "severity": [{"type": "CVSS_V3", "score": 6.1}],
                        "affected": [{"ranges": [{"events": [{"fixed": "2.31.0"}]}]}],
                    }
                ],
            ),
        ]

        scanner = CVEScanner(cache=OSVCache(default_ttl_seconds=3600.0))
        result = scanner.scan_directory(str(self.test_dir))

        self.assertEqual(result.status, ScanStatus.FLAGGED)
        self.assertTrue(result.success)
        self.assertEqual(result.files_scanned_count, 2)
        self.assertEqual(len(result.findings), 2)

        # Inspect first finding (lodash)
        f_lodash = next(f for f in result.findings if f.package_name == "lodash")
        self.assertEqual(f_lodash.cve_id, "CVE-2020-8203")
        self.assertEqual(f_lodash.severity, Severity.HIGH)
        self.assertEqual(f_lodash.fixed_version, "4.17.19")

        # Inspect second finding (requests)
        f_requests = next(f for f in result.findings if f.package_name == "requests")
        self.assertEqual(f_requests.cve_id, "CVE-2023-32681")
        self.assertEqual(f_requests.severity, Severity.MEDIUM)
        self.assertEqual(f_requests.fixed_version, "2.31.0")

        # Verify contract result evaluation
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "failed")
        self.assertEqual(contract_res.severity_counts["high"], 1)
        self.assertEqual(contract_res.severity_counts["medium"], 1)

    @patch.object(OSVClient, "query_dependencies")
    def test_network_timeout_fail_closed_default(self, mock_query):
        """Tests that OSV timeout with fail_open_on_osv_unavailable=False produces ScanStatus.ERROR."""
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"react": "18.2.0"}}), encoding="utf-8")

        mock_query.side_effect = OSVTimeoutError("Connection timed out after 10.0s", timeout=10.0)

        scanner = CVEScanner(fail_open_on_osv_unavailable=False)
        result = scanner.scan_directory(str(self.test_dir))

        self.assertEqual(result.status, ScanStatus.ERROR)
        self.assertFalse(result.success)
        self.assertIn("OSV.dev API unavailable (network failure / timeout)", result.error_message)
        self.assertIn("timed out", result.error_message)

        # Contract evaluation must gate to "error"
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "error")

    @patch.object(OSVClient, "query_dependencies")
    def test_network_timeout_fail_open_configurable(self, mock_query):
        """Tests that OSV timeout with fail_open_on_osv_unavailable=True produces ScanStatus.PASSED with note."""
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"react": "18.2.0"}}), encoding="utf-8")

        mock_query.side_effect = OSVTimeoutError("OSV API outage", timeout=10.0)

        scanner = CVEScanner(fail_open_on_osv_unavailable=True)
        result = scanner.scan_directory(str(self.test_dir))

        self.assertEqual(result.status, ScanStatus.PASSED)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 0)
        self.assertIsNotNone(result.error_message)
        self.assertIn("CVE check skipped due to OSV.dev unavailability", result.error_message)

        # Contract evaluation must pass because operator explicitly chose fail-open
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "passed")

    @patch.object(OSVClient, "query_dependencies")
    def test_cache_hit_avoids_network_call_within_ttl(self, mock_query):
        """Verifies that identical dependency queries within TTL hit cache and skip network."""
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}), encoding="utf-8")

        mock_query.return_value = [
            (
                DeclaredDependency("lodash", "4.17.15", True, "npm", str(pkg_json), 3),
                [
                    {
                        "id": "GHSA-p6mc-m468-83gw",
                        "summary": "Prototype Pollution in lodash",
                        "aliases": ["CVE-2020-8203"],
                        "severity": [{"type": "CVSS_V3", "score": 7.5}],
                    }
                ],
            )
        ]

        cache = OSVCache(default_ttl_seconds=3600.0)
        scanner = CVEScanner(cache=cache)

        # First scan pass - must query client
        res1 = scanner.scan_directory(str(self.test_dir))
        self.assertEqual(mock_query.call_count, 1)
        self.assertEqual(len(res1.findings), 1)

        # Second scan pass on identical dependency - must hit cache and avoid network
        res2 = scanner.scan_directory(str(self.test_dir))
        self.assertEqual(mock_query.call_count, 1, "Cache hit must NOT perform an additional network call")
        self.assertEqual(len(res2.findings), 1)
        self.assertEqual(res2.findings[0].rule_id, "GHSA-p6mc-m468-83gw")

    @patch.object(OSVClient, "query_dependencies")
    def test_cache_ttl_expiration_triggers_new_query(self, mock_query):
        """Verifies that expired cache entries trigger a fresh query."""
        import time
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"axios": "0.21.1"}}), encoding="utf-8")

        mock_query.return_value = [
            (
                DeclaredDependency("axios", "0.21.1", True, "npm", str(pkg_json), 3),
                [],
            )
        ]

        # TTL of 0.05 seconds
        cache = OSVCache(default_ttl_seconds=0.05)
        scanner = CVEScanner(cache=cache)

        scanner.scan_directory(str(self.test_dir))
        self.assertEqual(mock_query.call_count, 1)

        # Wait for cache entry to expire
        time.sleep(0.08)

        scanner.scan_directory(str(self.test_dir))
        self.assertEqual(mock_query.call_count, 2, "Expired cache entry must trigger a new query")

    @patch.object(OSVClient, "query_dependencies")
    def test_check_cve_flag_false_skips_scan(self, mock_query):
        """Verifies check_cve=False skips manifest processing and returns clean PASSED result."""
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"vulnerable-pkg": "1.0.0"}}), encoding="utf-8")

        scanner = CVEScanner(check_cve=False)
        result = scanner.scan_directory(str(self.test_dir))

        self.assertEqual(result.status, ScanStatus.PASSED)
        self.assertTrue(result.success)
        self.assertEqual(result.files_scanned_count, 0)
        self.assertEqual(len(result.findings), 0)
        mock_query.assert_not_called()

    @patch.object(OSVClient, "query_dependencies")
    def test_scan_package_returns_contract_result(self, mock_query):
        """Verifies canonical scan_package returns PackageScanResult."""
        pkg_json = self.test_dir / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"clean-pkg": "1.0.0"}}), encoding="utf-8")

        mock_query.return_value = [
            (DeclaredDependency("clean-pkg", "1.0.0", True, "npm", str(pkg_json), 3), [])
        ]

        contract_res = scan_package(str(self.test_dir))
        self.assertIsInstance(contract_res, PackageScanResult)
        self.assertEqual(contract_res.status, "passed")
        self.assertEqual(contract_res.findings, [])

    def test_ignores_ignored_directories(self):
        """Verifies manifests inside node_modules or .git directories are ignored."""
        nm_dir = self.test_dir / "node_modules" / "subpkg"
        nm_dir.mkdir(parents=True)
        (nm_dir / "package.json").write_text("{}", encoding="utf-8")

        scanner = CVEScanner(cache=OSVCache())
        result = scanner.scan_directory(str(self.test_dir))

        self.assertEqual(result.status, ScanStatus.PASSED)
        self.assertEqual(result.files_scanned_count, 0)


if __name__ == "__main__":
    unittest.main()


