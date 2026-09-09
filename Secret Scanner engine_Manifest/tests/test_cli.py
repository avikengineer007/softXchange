"""Unit tests for the standalone secrets-scan CLI entry point."""

import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from secrets_scanner.cli import Colors, build_parser, format_human_report, main, should_use_color
from secrets_scanner.contract import ContractStatus, PackageScanResult, ScanMetadata
from secrets_scanner.models import Confidence, Finding, Severity


class TestCliEntryPoint(unittest.TestCase):

    def test_parser_flag_aliases(self):
        """Confirms parser handles path, --history, --allowlist, and --json flags."""
        parser = build_parser()
        
        args = parser.parse_args(["my_repo", "--history", "--allowlist", "allow.json", "--json"])
        self.assertEqual(args.path, "my_repo")
        self.assertTrue(args.history)
        self.assertEqual(args.allowlist, "allow.json")
        self.assertTrue(args.json)

        # Alternate aliases
        args_alt = parser.parse_args(["my_repo", "--scan-history", "--allowlist-config", "allow.json"])
        self.assertTrue(args_alt.history)
        self.assertEqual(args_alt.allowlist, "allow.json")
        self.assertFalse(args_alt.json)

    def test_no_color_environment_variable(self):
        """Confirms that NO_COLOR disables ANSI coloring per https://no-color.org/."""
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(should_use_color())
            colors = Colors(enabled=should_use_color())
            self.assertEqual(colors.status("failed"), "FAILED")
            self.assertNotIn("\033[", colors.status("failed"))

        with patch.dict(os.environ, {}, clear=True):
            with patch("sys.stdout.isatty", return_value=True):
                self.assertTrue(should_use_color())
                colors = Colors(enabled=True)
                self.assertIn("\033[", colors.status("failed"))

    def test_human_readable_report_groups_by_severity(self):
        """Confirms that human-readable output groups findings by severity."""
        crit_finding = Finding(
            file_path="auth.py",
            line_number=1,
            rule_id="SLACK_TOKEN",
            rule_name="Slack Token",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            redacted_snippet="SLACK_TOKEN = 'xoxb...'",
            description="Slack bot token",
            commit_hash="abcdef123456",
        )
        high_finding = Finding(
            file_path="docs.py",
            line_number=5,
            rule_id="HIGH_ENTROPY_TOKEN",
            rule_name="High Entropy Token",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            redacted_snippet="text = '...'",
            description="Entropy string",
        )
        result = PackageScanResult(
            status=ContractStatus.FAILED.value,
            findings=[high_finding, crit_finding],
            severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0},
            metadata=ScanMetadata(0.05, 2, 0, True),
        )

        colors = Colors(enabled=False)
        report = format_human_report(result, "sample_dir", colors)

        # Confirm severity section headers exist in order
        self.assertIn("--- CRITICAL FINDINGS (1) ---", report)
        self.assertIn("--- HIGH FINDINGS (1) ---", report)
        crit_idx = report.index("--- CRITICAL FINDINGS")
        high_idx = report.index("--- HIGH FINDINGS")
        self.assertLess(crit_idx, high_idx)

        # Confirm commit hash is displayed
        self.assertIn("Commit     : abcdef123456", report)

    def test_cli_exit_code_passed(self):
        """Confirms CLI returns 0 on clean scan."""
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "main.py"), "w") as f:
                f.write("print('clean code')\n")
            
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                exit_code = main([td, "--json"])

            self.assertEqual(exit_code, 0)
            data = json.loads(mock_stdout.getvalue())
            self.assertEqual(data["status"], "passed")

    def test_cli_exit_code_failed(self):
        """Confirms CLI returns 1 on failed scan with blocking secrets."""
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "auth.py"), "w") as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
            
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                exit_code = main([td, "--json"])

            self.assertEqual(exit_code, 1)
            data = json.loads(mock_stdout.getvalue())
            self.assertEqual(data["status"], "failed")

    def test_cli_exit_code_error(self):
        """Confirms CLI returns 2 on unhandled error or missing directory."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = main(["Z:/non_existent_folder_xyz", "--json"])

        self.assertEqual(exit_code, 2)
        data = json.loads(mock_stdout.getvalue())
        self.assertEqual(data["status"], "error")


class TestCombinedScanPackageCLI(unittest.TestCase):
    """Tests scan-package combined CLI runner integrating secrets, static, and cve engines."""

    def test_scan_package_cli_runs_all_three_engines_by_default(self):
        """Confirms scan-package includes secrets + static + cve by default."""
        from static_analysis.cli import main_combined

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "app.py"), "w") as f:
                f.write("print('clean app')\n")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                exit_code = main_combined([td])

            self.assertEqual(exit_code, 0)
            output = mock_stdout.getvalue()
            self.assertIn("COMBINED SECURITY SCAN REPORT (SECRETS + STATIC ANALYSIS + CVE CHECK)", output)

    def test_scan_package_cli_no_cve_flag(self):
        """Confirms --no-cve-scan excludes cve_check from combined scan."""
        from static_analysis.cli import main_combined

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "app.py"), "w") as f:
                f.write("print('clean app')\n")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                exit_code = main_combined([td, "--no-cve-scan"])

            self.assertEqual(exit_code, 0)
            output = mock_stdout.getvalue()
            self.assertIn("COMBINED SECURITY SCAN REPORT (SECRETS + STATIC ANALYSIS)", output)
            self.assertNotIn("CVE CHECK", output)

    def test_static_scan_cli_with_cve_scan_flag(self):
        """Confirms static-scan --with-cve-scan includes CVE checking."""
        from static_analysis.cli import main as static_main

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "app.py"), "w") as f:
                f.write("print('clean app')\n")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                exit_code = static_main([td, "--with-cve-scan"])

            self.assertEqual(exit_code, 0)
            output = mock_stdout.getvalue()
            self.assertIn("COMBINED SECURITY SCAN REPORT (STATIC ANALYSIS + CVE CHECK)", output)


if __name__ == "__main__":
    unittest.main()
