"""Unit tests for the SecretsScanner orchestrator and end-to-end integration."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from secrets_scanner.models import Confidence, ScanStatus, Severity
from secrets_scanner.scanner import SecretsScanner


class TestSecretsScanner(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "package")
        self.scanner = SecretsScanner()

    def test_fixture_directory_scan(self):
        result = self.scanner.scan_directory(self.fixtures_dir)
        
        self.assertTrue(result.success)
        self.assertEqual(result.status, ScanStatus.FLAGGED)
        self.assertGreater(len(result.findings), 0)
        
        # Verify findings per file
        findings_by_file = {}
        for f in result.findings:
            fname = os.path.basename(f.file_path)
            findings_by_file.setdefault(fname, []).append(f)

        # 1. aws_secret.py must contain AWS findings
        self.assertIn("aws_secret.py", findings_by_file)
        aws_rule_ids = [f.rule_id for f in findings_by_file["aws_secret.py"]]
        self.assertIn("AWS_ACCESS_KEY_ID", aws_rule_ids)
        self.assertIn("AWS_SECRET_ACCESS_KEY", aws_rule_ids)

        # 2. entropy_secret.json must contain high entropy finding
        self.assertIn("entropy_secret.json", findings_by_file)
        entropy_rule_ids = [f.rule_id for f in findings_by_file["entropy_secret.json"]]
        self.assertIn("HIGH_ENTROPY_TOKEN", entropy_rule_ids)

        # 3. clean_code.py must have 0 findings
        self.assertNotIn("clean_code.py", findings_by_file)

        # 4. sample_binary.bin must be skipped as binary
        skipped_map = {os.path.basename(s.file_path): s.reason for s in result.files_skipped}
        self.assertIn("sample_binary.bin", skipped_map)
        self.assertEqual(skipped_map["sample_binary.bin"], "binary")

        # 5. node_modules and .git must be skipped
        self.assertIn("node_modules", skipped_map)
        self.assertEqual(skipped_map["node_modules"], "ignored_directory")
        self.assertIn(".git", skipped_map)
        self.assertEqual(skipped_map[".git"], "ignored_directory")

    def test_clean_directory_scan(self):
        with tempfile.TemporaryDirectory() as clean_dir:
            with open(os.path.join(clean_dir, "utils.py"), "w") as f:
                f.write('def add(a, b):\n    return a + b\n')
            with open(os.path.join(clean_dir, "README.md"), "w") as f:
                f.write('# Documentation\nThis is a clean module.')
                
            result = self.scanner.scan_directory(clean_dir)
            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.PASSED)
            self.assertEqual(len(result.findings), 0)
            self.assertEqual(result.files_scanned_count, 2)

    def test_fail_closed_nonexistent_directory(self):
        result = self.scanner.scan_directory("non_existent_directory_12345")
        self.assertFalse(result.success)
        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertIsNotNone(result.error_message)

    def test_fail_closed_budget_exceeded(self):
        with tempfile.TemporaryDirectory() as test_dir:
            for i in range(10):
                with open(os.path.join(test_dir, f"file_{i}.txt"), "w") as f:
                    f.write("content")
                    
            # Scanner with max_total_files = 3
            strict_scanner = SecretsScanner(max_total_files=3)
            result = strict_scanner.scan_directory(test_dir)
            
            self.assertFalse(result.success)
            self.assertEqual(result.status, ScanStatus.FAILED)
            self.assertIn("ScanBudgetExceeded", result.error_message or "")

    def test_placeholder_suppression(self):
        with tempfile.TemporaryDirectory() as test_dir:
            with open(os.path.join(test_dir, "config.py"), "w") as f:
                f.write('API_KEY = "your_api_key_here"\nPASSWORD = "changeme"\n')
                
            # Default scanner suppresses placeholders
            result = self.scanner.scan_directory(test_dir)
            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.PASSED)
            self.assertEqual(len(result.findings), 0)

    def test_custom_allowlist_suppression(self):
        with tempfile.TemporaryDirectory() as test_dir:
            stripe_val = "sk_" + "live_51Abcdefghijklmnopqrstuvwxyz"
            with open(os.path.join(test_dir, "config.py"), "w") as f:
                f.write(f'STRIPE_KEY = "{stripe_val}"\n')
                
            # Allowlist specific known test key
            scanner = SecretsScanner(allowlist=[stripe_val])
            result = scanner.scan_directory(test_dir)
            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.PASSED)
            self.assertEqual(len(result.findings), 0)

    def test_no_raw_secret_leakage(self):
        result = self.scanner.scan_directory(self.fixtures_dir)
        
        # Raw secret values from fixtures
        raw_secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0",
        ]
        
        for finding in result.findings:
            # Check redacted snippet preserves safety
            for raw_sec in raw_secrets:
                self.assertNotIn(
                    raw_sec,
                    finding.redacted_snippet,
                    f"Raw secret {raw_sec} leaked in snippet: {finding.redacted_snippet}"
                )
            # Verify redacted snippet contains masking chars
            self.assertIn("*", finding.redacted_snippet)

    def test_confidence_field_classification(self):
        # 1. Format-specific rule -> HIGH confidence
        slack_token = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
        slack_line = f'slack_token = "{slack_token}"'
        findings = self.scanner.scan_line(slack_line, 1, "services/slack.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SLACK_TOKEN")
        self.assertEqual(findings[0].confidence, Confidence.HIGH)

        # 2. Generic secret assignment -> MEDIUM confidence
        generic_line = 'secret = "my_custom_production_secret_key"'
        findings2 = self.scanner.scan_line(generic_line, 1, "config.py")
        self.assertEqual(len(findings2), 1)
        self.assertEqual(findings2[0].rule_id, "GENERIC_SECRET_ASSIGNMENT")
        self.assertEqual(findings2[0].confidence, Confidence.MEDIUM)

        # 3. High entropy token -> MEDIUM (when well above threshold) or LOW
        entropy_line = 'blob = "c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0"'
        findings3 = self.scanner.scan_line(entropy_line, 1, "data.json")
        self.assertEqual(len(findings3), 1)
        self.assertEqual(findings3[0].rule_id, "HIGH_ENTROPY_TOKEN")
        self.assertIn(findings3[0].confidence, (Confidence.MEDIUM, Confidence.LOW))

    def test_overlapping_rule_deduplication(self):
        # Line matches keywords that could trigger HARDCODED_PASSWORD and GENERIC_SECRET_ASSIGNMENT
        line = 'password = "SuperSecretPassword123!"'
        findings = self.scanner.scan_line(line, 1, "settings.py")

        # Must report exactly 1 finding without duplicates on the same span
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HARDCODED_PASSWORD")

        # Line matches AWS_SECRET_ACCESS_KEY and could match GENERIC_SECRET_ASSIGNMENT
        line2 = 'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        findings2 = self.scanner.scan_line(line2, 2, "aws.py")
        self.assertEqual(len(findings2), 1)
        self.assertEqual(findings2[0].rule_id, "AWS_SECRET_ACCESS_KEY")
        self.assertEqual(findings2[0].confidence, Confidence.HIGH)

    def test_allowlist_config_file_suppression_and_audit(self):
        with tempfile.TemporaryDirectory() as test_dir:
            # Create a fixture file with a secret
            fixture_file = os.path.join(test_dir, "test_fixture.py")
            with open(fixture_file, "w") as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')

            # Create another file with an actual secret
            prod_file = os.path.join(test_dir, "production.py")
            with open(prod_file, "w") as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')

            # Create an allowlist configuration file targeting only test_fixture.py
            allowlist_file = os.path.join(test_dir, "allowlist.json")
            with open(allowlist_file, "w") as f:
                json.dump({
                    "allowlist": [
                        {
                            "rule_id": "AWS_ACCESS_KEY_ID",
                            "file_path": "test_fixture.py",
                            "reason": "Test fixture credentials"
                        }
                    ]
                }, f)

            scanner = SecretsScanner(allowlist_config=allowlist_file)
            result = scanner.scan_directory(test_dir)

            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.FLAGGED)
            
            # The test_fixture.py finding must be suppressed
            finding_paths = [f.file_path for f in result.findings]
            self.assertNotIn(fixture_file, finding_paths)
            self.assertIn(prod_file, finding_paths)

            # The suppressed finding MUST be recorded for auditability
            self.assertEqual(len(result.suppressed_findings), 1)
            suppressed = result.suppressed_findings[0]
            self.assertEqual(suppressed.rule_id, "AWS_ACCESS_KEY_ID")
            self.assertEqual(suppressed.reason, "Test fixture credentials")
            self.assertIn(os.path.basename(fixture_file), suppressed.file_path)

    def test_enhanced_placeholder_suppression(self):
        with tempfile.TemporaryDirectory() as test_dir:
            sample_file = os.path.join(test_dir, "placeholders.py")
            with open(sample_file, "w") as f:
                f.write(
                    'API_KEY = "xxx"\n'
                    'SECRET = "<REDACTED>"\n'
                    'TOKEN = "[REDACTED]"\n'
                    'PASSWORD = "{REDACTED}"\n'
                    'DUMMY = "changeme"\n'
                    'USER_KEY = "your_api_key_here"\n'
                )

            result = self.scanner.scan_directory(test_dir)
            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.PASSED)
            self.assertEqual(len(result.findings), 0)


if __name__ == "__main__":
    unittest.main()

