"""Unit tests for the allowlist mechanism and path matching security."""

import json
import os
import tempfile
import unittest
from secrets_scanner.allowlist import (
    AllowlistConfig,
    AllowlistEntry,
    load_allowlist_config,
    normalize_pattern_path,
    path_matches_pattern,
)


class TestAllowlist(unittest.TestCase):

    def test_normalize_pattern_path_safety(self):
        # Forward slashes and strip leading ./
        self.assertEqual(normalize_pattern_path("tests\\fixtures\\sample.py"), "tests/fixtures/sample.py")
        self.assertEqual(normalize_pattern_path("./tests/fixtures/**"), "tests/fixtures/**")
        self.assertEqual(normalize_pattern_path(".env.example"), ".env.example")

        # Path traversal escaping outside target scope must raise ValueError
        with self.assertRaises(ValueError):
            normalize_pattern_path("../outside.py")
            
        with self.assertRaises(ValueError):
            normalize_pattern_path("fixtures/../../escaping.py")

    def test_path_matches_pattern(self):
        # Exact match
        self.assertTrue(path_matches_pattern("config/dev.env", "config/dev.env"))
        self.assertTrue(path_matches_pattern("config\\dev.env", "config/dev.env"))

        # Basename pattern match
        self.assertTrue(path_matches_pattern(".env.example", ".env.example"))
        self.assertTrue(path_matches_pattern("nested/folder/.env.example", ".env.example"))
        self.assertTrue(path_matches_pattern("nested/folder/.env.example", "*.env.example"))

        # Glob with **
        self.assertTrue(path_matches_pattern("tests/fixtures/package/aws_secret.py", "fixtures/**"))
        self.assertTrue(path_matches_pattern("tests/fixtures/package/aws_secret.py", "tests/fixtures/**"))
        self.assertTrue(path_matches_pattern("tests/fixtures/package/aws_secret.py", "**/aws_secret.py"))
        self.assertTrue(path_matches_pattern("tests/fixtures/package/sub/deep/secret.py", "tests/fixtures/**"))

        # Non-matching paths
        self.assertFalse(path_matches_pattern("src/main.py", "fixtures/**"))
        self.assertFalse(path_matches_pattern("src/config.py", "*.env.example"))

    def test_allowlist_config_from_dict(self):
        # Structure with 'allowlist'
        config1 = AllowlistConfig.from_dict({
            "allowlist": [
                {
                    "rule_id": "AWS_ACCESS_KEY_ID",
                    "file_path": "tests/fixtures/**",
                    "reason": "Test fixture credentials"
                }
            ]
        })
        self.assertEqual(len(config1.entries), 1)
        self.assertEqual(config1.entries[0].rule_id, "AWS_ACCESS_KEY_ID")

        # Structure with 'accepted_findings'
        config2 = AllowlistConfig.from_dict({
            "accepted_findings": [
                {
                    "rule_id": "*",
                    "file_path": ".env.example",
                    "reason": "Sample env template"
                }
            ]
        })
        self.assertEqual(len(config2.entries), 1)
        self.assertEqual(config2.entries[0].rule_id, "*")

        # Structure with raw list
        config3 = AllowlistConfig.from_dict([
            {
                "rule_id": "SLACK_TOKEN",
                "file_path": "tests/mock_slack.py",
            }
        ])
        self.assertEqual(len(config3.entries), 1)
        self.assertEqual(config3.entries[0].rule_id, "SLACK_TOKEN")

    def test_allowlist_match_and_wildcard(self):
        config = AllowlistConfig.from_dict({
            "allowlist": [
                {
                    "rule_id": "AWS_ACCESS_KEY_ID",
                    "file_path": "tests/fixtures/**",
                    "reason": "Test AWS credentials"
                },
                {
                    "rule_id": "*",
                    "file_path": "*.env.example",
                    "reason": "Environment template"
                }
            ]
        })

        # Match specific rule and path
        reason1 = config.match("AWS_ACCESS_KEY_ID", "tests/fixtures/package/aws_secret.py")
        self.assertEqual(reason1, "Test AWS credentials")

        # Different rule on same path should NOT match
        self.assertIsNone(config.match("GITHUB_TOKEN", "tests/fixtures/package/aws_secret.py"))

        # Wildcard rule should match ANY rule on the matching path
        reason2 = config.match("GENERIC_SECRET_ASSIGNMENT", "config/.env.example")
        self.assertEqual(reason2, "Environment template")

        reason3 = config.match("GOOGLE_API_KEY", "config/.env.example")
        self.assertEqual(reason3, "Environment template")

        # Non-matching path
        self.assertIsNone(config.match("AWS_ACCESS_KEY_ID", "src/auth/service.py"))

    def test_load_allowlist_config_from_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            json.dump({
                "allowlist": [
                    {
                        "rule_id": "TWILIO_KEY",
                        "file_path": "tests/fixtures/twilio_test.py",
                        "reason": "Mock twilio keys"
                    }
                ]
            }, tmp)
            tmp_path = tmp.name

        try:
            config = load_allowlist_config(tmp_path)
            self.assertIsNotNone(config)
            self.assertEqual(len(config.entries), 1)
            reason = config.match("TWILIO_KEY", "tests/fixtures/twilio_test.py")
            self.assertEqual(reason, "Mock twilio keys")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
