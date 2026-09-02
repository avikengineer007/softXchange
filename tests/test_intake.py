"""Comprehensive test suite for scan-service upload intake with GitHub URL support."""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from secrets_scanner.contract import ContractStatus, PackageScanResult, ScanMetadata
from secrets_scanner.intake import (
    CloneError,
    CredentialError,
    EncryptedEnvelope,
    EnvelopeCipher,
    GitHubAppCredentialStore,
    GitHubAppGrant,
    IntakeError,
    IntakePipeline,
    IntakeSource,
    ListingStatus,
    ListingVersion,
    LocalRootKeyKMSProvider,
    UploadRecord,
    normalize_repo_url,
    safe_clone_github_repo,
    sanitize_text,
)
from secrets_scanner.models import Finding, Severity, Confidence
from secrets_scanner.orchestrator import scan_package


def _init_local_git_repo(repo_dir: str, add_secret: bool = False) -> str:
    """Helper to initialize a real git repository on disk with an initial commit."""
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo_dir, check=True)
    
    file_path = os.path.join(repo_dir, "app.py")
    with open(file_path, "w", encoding="utf-8") as f:
        if add_secret:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        else:
            f.write('print("Hello safe world")\n')
            
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
    
    sha_proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True)
    return sha_proc.stdout.strip()


class TestIntakeModelsAndEncryption(unittest.TestCase):

    def setUp(self):
        self.kms = LocalRootKeyKMSProvider()
        self.cipher = EnvelopeCipher(self.kms)
        self.store = GitHubAppCredentialStore(self.cipher)

    def test_url_normalization(self):
        self.assertEqual(normalize_repo_url("https://github.com/org/repo.git"), "https://github.com/org/repo")
        self.assertEqual(normalize_repo_url("https://github.com/org/repo/"), "https://github.com/org/repo")
        self.assertEqual(normalize_repo_url("https://user:pass@github.com/org/repo"), "https://github.com/org/repo")
        with self.assertRaises(ValueError):
            normalize_repo_url("ftp://github.com/org/repo")
        with self.assertRaises(ValueError):
            normalize_repo_url("https://github.com/incomplete")

    def test_envelope_encryption_and_decryption(self):
        secret_token = "ghs_testToken1234567890abcdefghijklmnopqrstuvwxyz"
        envelope = self.cipher.encrypt(secret_token)
        
        self.assertIsInstance(envelope, EncryptedEnvelope)
        self.assertNotIn(secret_token, envelope.ciphertext_hex)
        self.assertNotIn(secret_token, repr(envelope))
        
        decrypted = self.cipher.decrypt(envelope)
        self.assertEqual(decrypted, secret_token)

    def test_scoped_credential_store_isolation(self):
        seller_a = "seller_alice"
        seller_b = "seller_bob"
        repo_1 = "https://github.com/alice-org/repo-one"
        repo_2 = "https://github.com/alice-org/repo-two"
        token_a = "ghs_AliceSecretToken111111111111111111111"
        
        grant = self.store.store_grant(seller_a, repo_1, token_a)
        self.assertIsInstance(grant, GitHubAppGrant)
        self.assertNotIn(token_a, repr(grant))
        self.assertNotIn(token_a, str(grant))
        self.assertNotIn(token_a, str(grant.to_dict()))
        
        # Valid retrieval
        retrieved = self.store.retrieve_decrypted_token(seller_a, repo_1)
        self.assertEqual(retrieved, token_a)
        
        # Cross-seller isolation: Seller B cannot access Seller A's grant
        with self.assertRaises(CredentialError):
            self.store.retrieve_decrypted_token(seller_b, repo_1)
            
        # Cross-repo isolation: Cannot use repo_1 grant on repo_2
        with self.assertRaises(CredentialError):
            self.store.retrieve_decrypted_token(seller_a, repo_2)

    def test_expired_grant_fails_closed(self):
        expired_time = time.time() - 100
        self.store.store_grant("seller_x", "https://github.com/x/repo", "ghs_expiredToken99999", expires_at=expired_time)
        with self.assertRaises(CredentialError) as ctx:
            self.store.retrieve_decrypted_token("seller_x", "https://github.com/x/repo")
        self.assertIn("expired", str(ctx.exception))


class TestSafeGitClone(unittest.TestCase):

    def setUp(self):
        self.temp_root = tempfile.mkdtemp(prefix="test_clone_")
        self.origin_dir = os.path.join(self.temp_root, "origin_repo")
        os.makedirs(self.origin_dir, exist_ok=True)
        self.initial_sha = _init_local_git_repo(self.origin_dir, add_secret=False)
        self.scratch_dir = os.path.join(self.temp_root, "scratch")

    def tearDown(self):
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def test_safe_clone_pins_commit_sha_and_no_credential_leak(self):
        """Test safe_clone_github_repo pins commit SHA and does not leak credentials in .git/config."""
        mock_token = "ghs_SuperSecretAppInstallationToken12345"
        
        # We patch git clone to clone from our local origin repository instead of remote github
        def mock_subprocess_run(cmd, *args, **kwargs):
            clean_cmd = list(cmd)
            # Rewrite remote github url to local origin directory for testing
            for i, arg in enumerate(clean_cmd):
                if "github.com" in arg:
                    clean_cmd[i] = self.origin_dir
            return subprocess._orig_run(clean_cmd, *args, **kwargs)

        subprocess._orig_run = subprocess.run
        with patch("subprocess.run", side_effect=mock_subprocess_run):
            resolved_sha = safe_clone_github_repo(
                repo_url="https://github.com/test-owner/test-repo",
                target_dir=self.scratch_dir,
                auth_token=mock_token,
            )
            
        self.assertEqual(resolved_sha, self.initial_sha)
        
        # Verify .git/config has NO token
        git_config_path = os.path.join(self.scratch_dir, ".git", "config")
        self.assertTrue(os.path.exists(git_config_path))
        with open(git_config_path, "r", encoding="utf-8") as f:
            config_content = f.read()
        self.assertNotIn(mock_token, config_content)

    def test_clone_failure_fails_closed_and_sanitizes_error(self):
        """Forced clone failure must fail closed, wipe scratch, and exclude secret tokens."""
        mock_token = "ghs_SecretTokenThatMustNeverAppearInLogs"
        non_existent_url = "https://github.com/nonexistent_org_xyz_9999/nonexistent_repo"
        
        with self.assertRaises(CloneError) as ctx:
            safe_clone_github_repo(
                repo_url=non_existent_url,
                target_dir=self.scratch_dir,
                auth_token=mock_token,
                timeout_seconds=5.0,
            )
            
        # Confirm scratch directory is completely cleaned up
        self.assertFalse(os.path.exists(self.scratch_dir))
        
        # Confirm zero-leak discipline: raw token is nowhere in error message or repr
        err_msg = str(ctx.exception)
        self.assertNotIn(mock_token, err_msg)
        self.assertNotIn(mock_token, repr(ctx.exception))


class TestIntakePipeline(unittest.TestCase):

    def setUp(self):
        self.temp_root = tempfile.mkdtemp(prefix="test_pipeline_")
        self.credential_store = GitHubAppCredentialStore()
        self.pipeline = IntakePipeline(credential_store=self.credential_store)

    def tearDown(self):
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def test_public_repo_clone_reaches_same_outcome_as_file_upload(self):
        """Public repo clone + scan reaches the same pass/fail outcomes as a file upload with equivalent content."""
        # 1. Prepare clean origin repo and clean zip
        clean_repo_dir = os.path.join(self.temp_root, "clean_repo")
        os.makedirs(clean_repo_dir, exist_ok=True)
        clean_sha = _init_local_git_repo(clean_repo_dir, add_secret=False)
        
        clean_zip_path = os.path.join(self.temp_root, "clean.zip")
        with zipfile.ZipFile(clean_zip_path, "w") as zf:
            zf.writestr("app.py", 'print("Hello safe world")\n')
            
        # 2. Prepare secret origin repo and secret zip
        secret_repo_dir = os.path.join(self.temp_root, "secret_repo")
        os.makedirs(secret_repo_dir, exist_ok=True)
        secret_sha = _init_local_git_repo(secret_repo_dir, add_secret=True)
        
        secret_zip_path = os.path.join(self.temp_root, "secret.zip")
        with zipfile.ZipFile(secret_zip_path, "w") as zf:
            zf.writestr("app.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        def mock_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0):
            # Target origin repo based on URL
            src = clean_repo_dir if "clean" in repo_url else secret_repo_dir
            shutil.copytree(src, target_dir, dirs_exist_ok=True)
            res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True)
            return res.stdout.strip()

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_clone):
            # Run clean file upload
            upl_file_clean, ver_file_clean = self.pipeline.submit_upload(
                listing_id="list_clean_file",
                version_id="v1",
                seller_id="seller_1",
                intake_source=IntakeSource.FILE_UPLOAD,
                archive_path=clean_zip_path,
            )
            # Run clean github_url
            upl_git_clean, ver_git_clean = self.pipeline.submit_upload(
                listing_id="list_clean_git",
                version_id="v1",
                seller_id="seller_1",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url="https://github.com/org/clean-repo",
            )
            
            # Both pass
            self.assertEqual(ver_file_clean.status, ListingStatus.PASSED)
            self.assertEqual(ver_git_clean.status, ListingStatus.PASSED)
            self.assertTrue(ver_git_clean.storage_location.startswith("live/"))
            self.assertEqual(ver_git_clean.resolved_commit_sha, clean_sha)

            # Run failing file upload
            upl_file_sec, ver_file_sec = self.pipeline.submit_upload(
                listing_id="list_sec_file",
                version_id="v1",
                seller_id="seller_1",
                intake_source=IntakeSource.FILE_UPLOAD,
                archive_path=secret_zip_path,
            )
            # Run failing github_url
            upl_git_sec, ver_git_sec = self.pipeline.submit_upload(
                listing_id="list_sec_git",
                version_id="v1",
                seller_id="seller_1",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url="https://github.com/org/secret-repo",
            )
            
            # Both fail due to secret finding
            self.assertEqual(ver_file_sec.status, ListingStatus.FAILED)
            self.assertEqual(ver_git_sec.status, ListingStatus.FAILED)
            self.assertGreaterEqual(len(ver_git_sec.scan_result.findings), 1)
            self.assertEqual(ver_git_sec.resolved_commit_sha, secret_sha)

    def test_private_repo_clone_with_mock_credential_succeeds(self):
        """Private repo clone using a stored installation credential succeeds and passes auth token."""
        private_repo_dir = os.path.join(self.temp_root, "private_repo")
        os.makedirs(private_repo_dir, exist_ok=True)
        expected_sha = _init_local_git_repo(private_repo_dir, add_secret=False)
        
        seller_id = "seller_private"
        repo_url = "https://github.com/corp/private-tool"
        token = "ghs_MockInstallationTokenPrivate123"
        
        self.credential_store.store_grant(seller_id, repo_url, token)
        
        token_received = None
        def mock_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            nonlocal token_received
            token_received = auth_token
            shutil.copytree(private_repo_dir, target_dir, dirs_exist_ok=True)
            res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True)
            return res.stdout.strip()

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_clone):
            upload_rec, version_rec = self.pipeline.submit_upload(
                listing_id="listing_priv",
                version_id="v1",
                seller_id=seller_id,
                intake_source=IntakeSource.GITHUB_URL,
                repo_url=repo_url,
                is_private=True,
            )
            
        self.assertEqual(token_received, token)
        self.assertEqual(version_rec.status, ListingStatus.PASSED)
        self.assertEqual(version_rec.resolved_commit_sha, expected_sha)
        self.assertTrue(version_rec.storage_location.startswith("live/"))

    def test_invalid_revoked_credential_fails_closed_with_scan_failed(self):
        """Invalid or revoked credential fails closed with status 'scan_failed', never left pending."""
        seller_id = "seller_revoked"
        repo_url = "https://github.com/corp/revoked-tool"
        
        # No grant exists for this repo
        upload_rec, version_rec = self.pipeline.submit_upload(
            listing_id="listing_revoked",
            version_id="v1",
            seller_id=seller_id,
            intake_source=IntakeSource.GITHUB_URL,
            repo_url=repo_url,
            is_private=True,
        )
        
        self.assertEqual(upload_rec.status, ListingStatus.SCAN_FAILED)
        self.assertEqual(version_rec.status, ListingStatus.SCAN_FAILED)
        self.assertIsNotNone(version_rec.error_message)
        self.assertNotIn("pending_scan", version_rec.status)

    def test_fail_closed_during_scanning_phase(self):
        """Crash or worker exception during SCANNING transitions to scan_failed, never left in scanning."""
        def mock_crash_clone(*args, **kwargs):
            raise RuntimeError("Mid-scan worker crash simulator")

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_crash_clone):
            upload_rec, version_rec = self.pipeline.submit_upload(
                listing_id="listing_crash",
                version_id="v1",
                seller_id="seller_crash",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url="https://github.com/corp/crasher",
            )
            
        self.assertEqual(upload_rec.status, ListingStatus.SCAN_FAILED)
        self.assertEqual(version_rec.status, ListingStatus.SCAN_FAILED)
        self.assertIn("Operation failed safely", version_rec.error_message)

    def test_zero_leak_discipline_during_forced_clone_failure(self):
        """Confirm no token value appears in log output, stored Finding, or error message during forced failure."""
        seller_id = "seller_leak_test"
        repo_url = "https://github.com/corp/leak-repo"
        secret_token = "ghs_ExtremelySensitivePrivateToken999"
        self.credential_store.store_grant(seller_id, repo_url, secret_token)

        def mock_failing_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            raise CloneError(f"HTTP 401 Unauthorized for {auth_token} at {repo_url}", [auth_token])

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_failing_clone):
            with self.assertLogs("scan_service.intake", level="ERROR") as log_cm:
                upload_rec, version_rec = self.pipeline.submit_upload(
                    listing_id="listing_leak",
                    version_id="v1",
                    seller_id=seller_id,
                    intake_source=IntakeSource.GITHUB_URL,
                    repo_url=repo_url,
                    is_private=True,
                )

        # Check version record error message
        self.assertNotIn(secret_token, version_rec.error_message)
        self.assertTrue("[REDACTED" in version_rec.error_message)
        
        # Check logs
        log_output = "\n".join(log_cm.output)
        self.assertNotIn(secret_token, log_output)

    def test_immutable_commit_sha_pinning_with_moving_target_ref(self):
        """Test that resolved_commit_sha is pinned immediately upon clone and immune to remote branch changes."""
        origin_dir = os.path.join(self.temp_root, "moving_origin")
        os.makedirs(origin_dir, exist_ok=True)
        first_sha = _init_local_git_repo(origin_dir, add_secret=False)
        
        pinned_sha_during_scan = None
        
        def mock_clone_and_move_upstream(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            # 1. Clone initial state
            shutil.copytree(origin_dir, target_dir, dirs_exist_ok=True)
            res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True)
            resolved = res.stdout.strip()
            
            # 2. Simulate upstream remote branch moving / force-pushed to a new commit
            with open(os.path.join(origin_dir, "app.py"), "a") as f:
                f.write("# moving commit\n")
            subprocess.run(["git", "commit", "-am", "Upstream moved"], cwd=origin_dir, capture_output=True)
            
            return resolved

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_clone_and_move_upstream):
            upload_rec, version_rec = self.pipeline.submit_upload(
                listing_id="listing_moving_ref",
                version_id="v1",
                seller_id="seller_1",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url="https://github.com/org/moving-repo",
            )
            
        # The stored resolved_commit_sha must match first_sha, NOT the moved upstream HEAD
        self.assertEqual(version_rec.resolved_commit_sha, first_sha)
        self.assertEqual(upload_rec.resolved_commit_sha, first_sha)

    def test_scratch_directory_cleanup_guarantee(self):
        """Scratch directory must be deleted under all outcomes (passed, failed, exception)."""
        created_scratch_dirs = []
        orig_mkdtemp = tempfile.mkdtemp
        
        def spy_mkdtemp(*args, **kwargs):
            td = orig_mkdtemp(*args, **kwargs)
            if "scan_scratch_" in td:
                created_scratch_dirs.append(td)
            return td

        clean_repo_dir = os.path.join(self.temp_root, "scratch_test_repo")
        os.makedirs(clean_repo_dir, exist_ok=True)
        _init_local_git_repo(clean_repo_dir, add_secret=False)

        def mock_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            shutil.copytree(clean_repo_dir, target_dir, dirs_exist_ok=True)
            return "1111222233334444555566667777888899990000"

        with patch("tempfile.mkdtemp", side_effect=spy_mkdtemp):
            with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_clone):
                # 1. Success case
                self.pipeline.submit_upload(
                    listing_id="l_clean",
                    version_id="v1",
                    seller_id="s1",
                    intake_source=IntakeSource.GITHUB_URL,
                    repo_url="https://github.com/org/scratch-repo",
                )
                # 2. Failure case
                with patch.object(self.pipeline, "scanner_fn", side_effect=Exception("Explosion")):
                    self.pipeline.submit_upload(
                        listing_id="l_err",
                        version_id="v1",
                        seller_id="s1",
                        intake_source=IntakeSource.GITHUB_URL,
                        repo_url="https://github.com/org/scratch-repo",
                    )

        self.assertGreaterEqual(len(created_scratch_dirs), 2)
        for d in created_scratch_dirs:
            self.assertFalse(os.path.exists(d), f"Scratch directory was not cleaned up: {d}")

    def test_explicit_resubmit_listing_version(self):
        """Seller-triggered re-scan creates new version with new ref and resolved SHA."""
        repo_dir = os.path.join(self.temp_root, "resubmit_repo")
        os.makedirs(repo_dir, exist_ok=True)
        sha_v1 = _init_local_git_repo(repo_dir, add_secret=False)
        
        # Second commit
        with open(os.path.join(repo_dir, "v2.txt"), "w") as f:
            f.write("v2 update\n")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Commit v2"], cwd=repo_dir, check=True, capture_output=True)
        sha_proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True)
        sha_v2 = sha_proc.stdout.strip()

        current_sha = sha_v1
        def mock_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            shutil.copytree(repo_dir, target_dir, dirs_exist_ok=True)
            if ref == "v2":
                return sha_v2
            return sha_v1

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_clone):
            # Version 1
            u1, v1 = self.pipeline.submit_upload(
                listing_id="listing_resubmit",
                version_id="v1",
                seller_id="seller_resubmit",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url="https://github.com/org/resubmit-repo",
            )
            self.assertEqual(v1.resolved_commit_sha, sha_v1)
            
            # Seller explicitly resubmits listing with ref='v2'
            u2, v2 = self.pipeline.resubmit_listing_version(
                listing_id="listing_resubmit",
                version_id="v2",
                seller_id="seller_resubmit",
                ref="v2",
            )
            self.assertEqual(v2.resolved_commit_sha, sha_v2)
            self.assertEqual(v2.status, ListingStatus.PASSED)


if __name__ == "__main__":
    unittest.main()
