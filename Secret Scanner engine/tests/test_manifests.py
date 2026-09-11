"""Unit tests for dependency manifest inspection in static analysis engine."""

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from secrets_scanner.models import Confidence, ScanStatus, Severity
from static_analysis.manifests import (
    inspect_manifest,
    load_denylist,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_requirements_txt,
)
from static_analysis.scanner import StaticAnalyzer, scan_directory, scan_package


class TestDependencyManifests(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures" / "static_analysis" / "manifests"

    # =========================================================================
    # Node.js (package.json) Tests
    # =========================================================================

    def test_clean_package_json(self):
        target = self.fixtures_dir / "clean_npm"
        result = scan_directory(str(target))

        self.assertEqual(result.status, ScanStatus.PASSED)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.files_scanned_count, 1)

    def test_unpinned_package_json(self):
        target = self.fixtures_dir / "unpinned_npm"
        result = scan_directory(str(target))

        self.assertEqual(result.status, ScanStatus.FLAGGED)
        self.assertEqual(len(result.findings), 2)
        for f in result.findings:
            self.assertEqual(f.rule_id, "MANIFEST_UNPINNED_DEPENDENCY")
            self.assertEqual(f.severity, Severity.LOW)
            self.assertEqual(f.confidence, Confidence.HIGH)
            self.assertIn("Pin", f.remediation_hint)

        # Contract status remains passed because LOW severity does not gate
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "passed")
        self.assertEqual(contract_res.severity_counts["low"], 2)

    def test_malicious_package_json(self):
        target = self.fixtures_dir / "malicious_npm"
        result = scan_directory(str(target))

        self.assertEqual(result.status, ScanStatus.FLAGGED)
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("MANIFEST_MALICIOUS_DEPENDENCY", rule_ids)

        mal_finding = next(f for f in result.findings if f.rule_id == "MANIFEST_MALICIOUS_DEPENDENCY")
        self.assertEqual(mal_finding.severity, Severity.CRITICAL)
        self.assertEqual(mal_finding.confidence, Confidence.HIGH)
        self.assertIn("crossenv", mal_finding.description)
        self.assertIn("Remove 'crossenv' immediately", mal_finding.remediation_hint)

        # Contract status gates to failed
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "failed")
        self.assertEqual(contract_res.severity_counts["critical"], 1)

    def test_malformed_package_json_fail_closed_error_path(self):
        target = self.fixtures_dir / "malformed_npm"
        result = scan_directory(str(target))

        # Confirms fail-closed behavior routes to ScanStatus.ERROR, not malware conviction
        self.assertEqual(result.status, ScanStatus.ERROR)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)
        self.assertIn("Unable to parse dependency manifest", result.error_message)
        self.assertIn("Please verify file syntax and resubmit", result.error_message)

        # Produces explicit MANIFEST_PARSE_ERROR finding
        self.assertEqual(len(result.findings), 1)
        err_finding = result.findings[0]
        self.assertEqual(err_finding.rule_id, "MANIFEST_PARSE_ERROR")
        self.assertEqual(err_finding.severity, Severity.HIGH)
        self.assertEqual(err_finding.confidence, Confidence.HIGH)
        self.assertIn("Check package.json for syntax formatting errors", err_finding.remediation_hint)

        # Contract result reflects 'error' status
        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "error")

    # =========================================================================
    # Python (requirements.txt) Tests
    # =========================================================================

    def test_clean_requirements_txt(self):
        target = self.fixtures_dir / "clean_pypi"
        result = scan_directory(str(target))

        self.assertEqual(result.status, ScanStatus.PASSED)
        self.assertEqual(len(result.findings), 0)

    def test_unpinned_requirements_txt(self):
        target = self.fixtures_dir / "unpinned_pypi"
        result = scan_directory(str(target))

        self.assertEqual(result.status, ScanStatus.FLAGGED)
        self.assertEqual(len(result.findings), 3)
        for f in result.findings:
            self.assertEqual(f.rule_id, "MANIFEST_UNPINNED_DEPENDENCY")
            self.assertEqual(f.severity, Severity.LOW)

    def test_malicious_requirements_txt(self):
        target = self.fixtures_dir / "malicious_pypi"
        result = scan_directory(str(target))

        self.assertEqual(result.status, ScanStatus.FLAGGED)
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("MANIFEST_MALICIOUS_DEPENDENCY", rule_ids)

        mal_finding = next(f for f in result.findings if f.rule_id == "MANIFEST_MALICIOUS_DEPENDENCY")
        self.assertEqual(mal_finding.severity, Severity.CRITICAL)
        self.assertEqual(mal_finding.confidence, Confidence.HIGH)
        self.assertIn("colourama", mal_finding.description)

        contract_res = result.to_contract_result()
        self.assertEqual(contract_res.status, "failed")

    # =========================================================================
    # Go (go.mod) and Rust (Cargo.toml) Tests
    # =========================================================================

    def test_go_mod_multi_line_and_single_require(self):
        go_mod_content = """module example.com/my/app

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/google/uuid v1.6.0 // indirect
)

require github.com/malware/evilpkg v0.1.0
"""
        deps, err = parse_go_mod(go_mod_content, "go.mod")
        self.assertIsNone(err)
        self.assertEqual(len(deps), 3)
        self.assertEqual(deps[0].name, "github.com/gin-gonic/gin")
        self.assertEqual(deps[0].version_spec, "v1.9.1")
        self.assertTrue(deps[0].is_pinned)

        # Denylist test on go.mod
        res = inspect_manifest("go.mod", go_mod_content)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].rule_id, "MANIFEST_MALICIOUS_DEPENDENCY")
        self.assertIn("github.com/malware/evilpkg", res.findings[0].description)

    def test_cargo_toml_parsing(self):
        cargo_content = """[package]
name = "my_crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
unpinned_crate = "*"
table_dep = { version = "0.4.2", features = ["derive"] }
"""
        deps, err = parse_cargo_toml(cargo_content, "Cargo.toml")
        self.assertIsNone(err)
        self.assertEqual(len(deps), 3)

        pinned_map = {d.name: d.is_pinned for d in deps}
        self.assertTrue(pinned_map["serde"])
        self.assertFalse(pinned_map["unpinned_crate"])
        self.assertTrue(pinned_map["table_dep"])

        res = inspect_manifest("Cargo.toml", cargo_content)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].rule_id, "MANIFEST_UNPINNED_DEPENDENCY")
        self.assertIn("unpinned_crate", res.findings[0].description)

    # =========================================================================
    # Optional Pass Flag & Config Tests
    # =========================================================================

    def test_optional_manifest_pass_flag_disables_inspection(self):
        target = self.fixtures_dir / "malicious_npm"

        # When enabled (default): flags malicious package
        res_enabled = scan_package(str(target), check_dependency_manifests=True)
        self.assertEqual(res_enabled.status, "failed")

        # When disabled via check_dependency_manifests=False: passes because manifests are skipped
        res_disabled = scan_package(str(target), check_dependency_manifests=False)
        self.assertEqual(res_disabled.status, "passed")
        self.assertEqual(len(res_disabled.findings), 0)

        # When disabled via checkDependencyManifests=False alias: passes
        res_alias = scan_package(str(target), checkDependencyManifests=False)
        self.assertEqual(res_alias.status, "passed")

    def test_single_file_direct_scan(self):
        pkg_json_file = self.fixtures_dir / "clean_npm" / "package.json"
        res = scan_directory(str(pkg_json_file))
        self.assertEqual(res.status, ScanStatus.PASSED)
        self.assertEqual(res.files_scanned_count, 1)

    def test_custom_denylist_path(self):
        custom_denylist = {
            "npm": ["custom-evil-pkg"]
        }
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
            json.dump(custom_denylist, tf)
            custom_path = tf.name

        try:
            content = json.dumps({"dependencies": {"custom-evil-pkg": "1.0.0"}})
            denylist = load_denylist(custom_path)
            res = inspect_manifest("package.json", content, denylist=denylist)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].rule_id, "MANIFEST_MALICIOUS_DEPENDENCY")
            self.assertIn("custom-evil-pkg", res.findings[0].description)
        finally:
            if os.path.exists(custom_path):
                os.unlink(custom_path)


if __name__ == "__main__":
    unittest.main()
