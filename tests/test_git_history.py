"""Unit tests for git commit history diff scanning and deduplication."""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from secrets_scanner.git_history import (
    GitHistoryScanError,
    is_git_repository,
    stream_git_diff_entries,
)
from secrets_scanner.models import ScanStatus
from secrets_scanner.scanner import SecretsScanner


def _init_git_repo(repo_dir: str):
    """Helper to initialize a clean git repo with basic committer config."""
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Security Tester"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo_dir, check=True, capture_output=True)


class TestGitHistoryScanning(unittest.TestCase):

    def test_subprocess_safety_and_shell_metacharacters(self):
        """Asserts that git history scanning uses shell=False and safe argument lists,
        even when paths contain dangerous shell metacharacters.
        """
        # Create a directory name containing shell metacharacters: spaces, ;, &, |, `, $()
        with tempfile.TemporaryDirectory() as base_tmp:
            weird_dir_name = "repo ; echo INJECTED & (echo test) `calc`"
            repo_path = os.path.join(base_tmp, weird_dir_name)
            os.makedirs(repo_path, exist_ok=True)
            _init_git_repo(repo_path)

            file_path = os.path.join(repo_path, "sample.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("initial commit\n")
            subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True, capture_output=True)

            # Spy on subprocess.Popen to verify shell=False and argument list
            real_popen = subprocess.Popen
            popen_calls = []

            def spy_popen(*args, **kwargs):
                popen_calls.append((args, kwargs))
                return real_popen(*args, **kwargs)

            with patch("subprocess.Popen", side_effect=spy_popen):
                entries = list(stream_git_diff_entries(repo_path, max_commits=10))

            self.assertGreater(len(popen_calls), 0)
            cmd_args, kwargs = popen_calls[0]
            # Must be invoked as a list of strings, never a raw shell string
            self.assertIsInstance(cmd_args[0], list)
            self.assertEqual(cmd_args[0][0], "git")
            # shell MUST be False
            self.assertFalse(kwargs.get("shell", False))

            # Verify stream ran successfully without shell injection
            self.assertGreater(len(entries), 0)
            self.assertEqual(entries[0].file_path, "sample.txt")

    def test_commit_and_remove_secret_detected(self):
        """Confirms that a secret committed in an early commit and deleted in a later commit
        is still detected when scan_history=True, and ignored when scan_history=False.
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            _init_git_repo(repo_dir)

            secret_file = os.path.join(repo_dir, "auth_service.py")
            
            # Commit 1: introduce hardcoded secret
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write('SLACK_TOKEN = "' + 'xoxb-' + '123456789012-1234567890123-abcdefghijklmnopqrstuvwx"\\n')
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
            p1 = subprocess.run(["git", "commit", "-m", "Add slack integration"], cwd=repo_dir, check=True, capture_output=True)
            
            # Commit 2: delete secret, replace with clean code
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write('SLACK_TOKEN = os.environ.get("SLACK_BOT_TOKEN")\n')
            subprocess.run(["git", "commit", "-am", "Remove hardcoded secret"], cwd=repo_dir, check=True, capture_output=True)

            # 1. Plain scan (scan_history=False) -> Working tree is clean, must pass
            scanner_default = SecretsScanner(scan_history=False)
            result_default = scanner_default.scan_directory(repo_dir)
            self.assertTrue(result_default.success)
            self.assertEqual(result_default.status, ScanStatus.PASSED)
            self.assertEqual(len(result_default.findings), 0)

            # 2. History scan (scan_history=True) -> Must detect historical commit
            scanner_history = SecretsScanner(scan_history=True)
            result_history = scanner_history.scan_directory(repo_dir)
            self.assertTrue(result_history.success)
            self.assertEqual(result_history.status, ScanStatus.FLAGGED)
            self.assertEqual(len(result_history.findings), 1)

            finding = result_history.findings[0]
            self.assertEqual(finding.rule_id, "SLACK_TOKEN")
            self.assertIsNotNone(finding.commit_hash)
            self.assertIn("auth_service.py", finding.file_path)
            self.assertIn("historical commit", finding.description)

    def test_working_tree_and_history_deduplication(self):
        """Confirms that a secret present in both working tree and commit history
        is reported ONCE, annotated with the commit hash.
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            _init_git_repo(repo_dir)

            config_file = os.path.join(repo_dir, "config.py")
            with open(config_file, "w", encoding="utf-8") as f:
                f.write('GOOGLE_API_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"\n')
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Add Google Maps API key"], cwd=repo_dir, check=True, capture_output=True)

            scanner = SecretsScanner(scan_history=True)
            result = scanner.scan_directory(repo_dir)

            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.FLAGGED)
            
            # Reported exactly once
            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding.rule_id, "GOOGLE_API_KEY")
            self.assertIsNotNone(finding.commit_hash)
            self.assertIn("also found in git commit", finding.description)

    def test_rename_diff_parsing(self):
        """Confirms that file renames with content changes correctly attribute findings
        to the destination file path and 1-indexed line numbers.
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            _init_git_repo(repo_dir)

            old_file = os.path.join(repo_dir, "legacy_config.py")
            with open(old_file, "w", encoding="utf-8") as f:
                f.write("# Legacy configuration\nPORT = 8080\n")
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

            # Rename file using git mv
            subprocess.run(["git", "mv", "legacy_config.py", "new_config.py"], cwd=repo_dir, check=True, capture_output=True)
            new_file = os.path.join(repo_dir, "new_config.py")
            with open(new_file, "a", encoding="utf-8") as f:
                f.write('TWILIO_KEY = "' + 'SK' + '0123456789abcdef0123456789abcdef"\\n')
            subprocess.run(["git", "commit", "-am", "Rename and add Twilio secret"], cwd=repo_dir, check=True, capture_output=True)

            # Remove secret in next commit
            with open(new_file, "w", encoding="utf-8") as f:
                f.write("# Legacy configuration\nPORT = 8080\n")
            subprocess.run(["git", "commit", "-am", "Remove Twilio secret"], cwd=repo_dir, check=True, capture_output=True)

            scanner = SecretsScanner(scan_history=True)
            result = scanner.scan_directory(repo_dir)

            self.assertTrue(result.success)
            self.assertEqual(result.status, ScanStatus.FLAGGED)
            self.assertEqual(len(result.findings), 1)

            finding = result.findings[0]
            self.assertEqual(finding.rule_id, "TWILIO_KEY")
            # Must be attributed to new_config.py, not legacy_config.py
            self.assertEqual(finding.file_path, "new_config.py")
            self.assertIsNotNone(finding.commit_hash)

    def test_fail_closed_on_corrupt_git_repo(self):
        """Confirms that a broken or corrupt .git directory causes the scan to fail closed
        with ScanStatus.FAILED and an error message, rather than silently passing.
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            git_dir = os.path.join(repo_dir, ".git")
            os.makedirs(git_dir, exist_ok=True)
            # Create corrupted HEAD pointing nowhere
            with open(os.path.join(git_dir, "HEAD"), "w") as f:
                f.write("corrupted git data\n")

            scanner = SecretsScanner(scan_history=True)
            result = scanner.scan_directory(repo_dir)

            # Must fail closed
            self.assertFalse(result.success)
            self.assertEqual(result.status, ScanStatus.FAILED)
            self.assertIn("GitHistoryScanError", result.error_message or "")

    def test_max_commits_bounding(self):
        """Confirms that max_commits actually bounds the history inspection depth,
        verifying that secrets beyond the commit cap are not inspected while
        secrets within the cap are detected.
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            _init_git_repo(repo_dir)

            # Commit 0 (oldest): introduce secret
            fpath = os.path.join(repo_dir, "auth.py")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write('SLACK_TOKEN = "' + 'xoxb-' + '123456789012-1234567890123-abcdefghijklmnopqrstuvwx"\n')
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Commit 0: add secret"], cwd=repo_dir, check=True, capture_output=True)

            # Commit 1: remove secret
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("# Clean file\n")
            subprocess.run(["git", "commit", "-am", "Commit 1: remove secret"], cwd=repo_dir, check=True, capture_output=True)

            # Commits 2, 3, 4: clean commits
            for i in range(2, 5):
                with open(fpath, "a", encoding="utf-8") as f:
                    f.write(f"# Comment line {i}\n")
                subprocess.run(["git", "commit", "-am", f"Commit {i}"], cwd=repo_dir, check=True, capture_output=True)

            # 1. Scanner with max_commits=2 (only inspects commits 4 and 3) -> Commit 0 is beyond boundary!
            scanner_capped = SecretsScanner(scan_history=True, max_commits=2)
            result_capped = scanner_capped.scan_directory(repo_dir)
            self.assertTrue(result_capped.success)
            self.assertEqual(result_capped.status, ScanStatus.PASSED)
            self.assertEqual(len(result_capped.findings), 0)

            # 2. Scanner with max_commits=5 (inspects all 5 commits) -> Commit 0 is reached and secret detected!
            scanner_full = SecretsScanner(scan_history=True, max_commits=5)
            result_full = scanner_full.scan_directory(repo_dir)
            self.assertTrue(result_full.success)
            self.assertEqual(result_full.status, ScanStatus.FLAGGED)
            self.assertEqual(len(result_full.findings), 1)
            self.assertEqual(result_full.findings[0].rule_id, "SLACK_TOKEN")

    def test_git_history_timeout_fail_closed(self):
        """Confirms that if git history scanning exceeds the wall-clock timeout,
        the process is terminated and GitHistoryScanError is raised, causing
        the scanner to fail closed (ScanStatus.FAILED).
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            _init_git_repo(repo_dir)

            fpath = os.path.join(repo_dir, "test.txt")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("Line 1\n")
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

            # 1. Direct stream test: times out and raises GitHistoryScanError
            with self.assertRaises(GitHistoryScanError) as ctx:
                list(stream_git_diff_entries(repo_dir, timeout_seconds=0.000001))
            self.assertIn("timeout", str(ctx.exception).lower())

            # 2. Scanner integration test: fails closed on GitHistoryScanError
            with patch("secrets_scanner.scanner.stream_git_diff_entries", side_effect=GitHistoryScanError("Git history scan exceeded wall-clock timeout (30.0s)")):
                scanner = SecretsScanner(scan_history=True)
                result = scanner.scan_directory(repo_dir)

            self.assertFalse(result.success)
            self.assertEqual(result.status, ScanStatus.FAILED)
            self.assertIn("GitHistoryScanError", result.error_message or "")
            self.assertIn("timeout", (result.error_message or "").lower())

    def test_git_history_byte_budget_exceeded_fail_closed(self):
        """Confirms that if git diff output volume exceeds max_total_bytes,
        the process is killed and the scan fails closed (ScanStatus.FAILED).
        """
        with tempfile.TemporaryDirectory() as repo_dir:
            _init_git_repo(repo_dir)

            fpath = os.path.join(repo_dir, "large_file.txt")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("A" * 1000 + "\n")
            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Large diff commit"], cwd=repo_dir, check=True, capture_output=True)

            # Remove file from working tree so working-tree walk stays at 0 bytes
            os.unlink(fpath)

            # Scanner with max_total_bytes=50 bytes (diff is ~1000 bytes)
            scanner = SecretsScanner(scan_history=True, max_total_bytes=50)
            result = scanner.scan_directory(repo_dir)

            # Must fail closed on git history diff budget
            self.assertFalse(result.success)
            self.assertEqual(result.status, ScanStatus.FAILED)
            self.assertIn("GitHistoryScanError", result.error_message or "")
            self.assertIn("budget", (result.error_message or "").lower())


if __name__ == "__main__":
    unittest.main()
