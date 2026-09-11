"""Unit tests for the post-intake scan-service orchestrator."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock

from secrets_scanner.contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    merge_package_results,
)
from secrets_scanner.models import Confidence, Finding, Severity, SuppressedFinding
from secrets_scanner.service_orchestrator import (
    DEFAULT_SCANNERS,
    InMemoryObjectStorage,
    InMemoryPostgresListingRepository,
    ScanOutcome,
    merge_scan_results,
    process_upload,
)


def _make_finding(rule_id: str, severity: Severity, file_path: str = "app.py") -> Finding:
    return Finding(
        file_path=file_path,
        line_number=12,
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=severity,
        confidence=Confidence.HIGH,
        redacted_snippet="secret = '****'",
        description=f"Detection for {rule_id}",
    )


class TestServiceOrchestrator(unittest.TestCase):

    def setUp(self):
        self.storage = InMemoryObjectStorage()
        self.repo = InMemoryPostgresListingRepository()
        self.test_dir = tempfile.mkdtemp(prefix="orch_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_scratch_dir(self, clean: bool = True) -> str:
        sd = tempfile.mkdtemp(prefix="scratch_pkg_")
        file_path = os.path.join(sd, "service.py")
        with open(file_path, "w", encoding="utf-8") as f:
            if clean:
                f.write("def handler():\n    return {'status': 'healthy'}\n")
            else:
                f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        return sd

    def test_passed_outcome_moves_to_live_and_cleans_scratch(self):
        """Clean package scan passes -> moves from pending/ to live/, updates Postgres to 'live', and deletes scratch."""
        scratch_dir = self._create_scratch_dir(clean=True)
        listing_id = "listing_clean_001"
        version = "v1.0.0"
        
        # Pre-seed pending package in object storage
        pending_key = f"pending/{listing_id}/{version}/package.tar.gz"
        self.storage.store[pending_key] = b"binary-data"

        outcome = process_upload(
            listing_id=listing_id,
            version=version,
            scratch_dir=scratch_dir,
            storage_client=self.storage,
            repository=self.repo,
        )

        # 1. Outcome attributes
        self.assertEqual(outcome.status, "live")
        self.assertEqual(outcome.overall_scan_status, "passed")
        self.assertEqual(len(outcome.findings), 0)
        self.assertEqual(outcome.storage_location, f"live/{listing_id}/{version}/")

        # 2. Object storage move verification
        self.assertFalse(self.storage.package_exists(f"pending/{listing_id}/{version}"))
        self.assertTrue(self.storage.package_exists(f"live/{listing_id}/{version}"))
        self.assertIn(f"live/{listing_id}/{version}/package.tar.gz", self.storage.store)

        # 3. Database persistence verification
        db_record = self.repo.get_listing_version(listing_id, version)
        self.assertIsNotNone(db_record)
        self.assertEqual(db_record["status"], "live")
        self.assertEqual(db_record["storage_location"], f"live/{listing_id}/{version}/")
        self.assertEqual(db_record["scan_result"]["findings"], [])

        # 4. Scratch directory cleanup verification
        self.assertFalse(os.path.exists(scratch_dir), "Scratch directory was not cleaned up!")

    def test_failed_outcome_leaves_in_pending_and_cleans_scratch(self):
        """Package with secrets fails -> stays in pending/ (never live), status 'scan_failed', stores findings, cleans scratch."""
        scratch_dir = self._create_scratch_dir(clean=False)
        listing_id = "listing_secret_002"
        version = "v1.0.0"
        
        pending_key = f"pending/{listing_id}/{version}/package.tar.gz"
        self.storage.store[pending_key] = b"binary-data"

        outcome = process_upload(
            listing_id=listing_id,
            version=version,
            scratch_dir=scratch_dir,
            storage_client=self.storage,
            repository=self.repo,
        )

        # 1. Outcome attributes
        self.assertEqual(outcome.status, "scan_failed")
        self.assertEqual(outcome.overall_scan_status, "failed")
        self.assertGreaterEqual(len(outcome.findings), 1)
        self.assertEqual(outcome.storage_location, f"pending/{listing_id}/{version}/")

        # 2. Object storage verification: never live/, remains pending/
        self.assertTrue(self.storage.package_exists(f"pending/{listing_id}/{version}"))
        self.assertFalse(self.storage.package_exists(f"live/{listing_id}/{version}"))

        # 3. Database persistence verification: stores full findings for seller view
        db_record = self.repo.get_listing_version(listing_id, version)
        self.assertIsNotNone(db_record)
        self.assertEqual(db_record["status"], "scan_failed")
        self.assertGreaterEqual(len(db_record["scan_result"]["findings"]), 1)
        self.assertEqual(db_record["scan_result"]["severity_counts"]["critical"], 1)

        # 4. Scratch directory cleanup verification
        self.assertFalse(os.path.exists(scratch_dir), "Scratch directory was not cleaned up!")

    def test_error_outcome_leaves_in_pending_and_cleans_scratch(self):
        """Scanner error -> stays in pending/, status 'scan_failed' (fail-closed), cleans scratch."""
        scratch_dir = self._create_scratch_dir(clean=True)
        listing_id = "listing_err_003"
        version = "v1.0.0"

        # Mock scanner returning error status
        def mock_error_scanner(path, **kwargs):
            return PackageScanResult(
                status=ContractStatus.ERROR.value,
                findings=[],
                severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
                error_message="ArchiveDecompressionTimeout: scan timed out",
            )

        outcome = process_upload(
            listing_id=listing_id,
            version=version,
            scratch_dir=scratch_dir,
            scanners=[mock_error_scanner],
            storage_client=self.storage,
            repository=self.repo,
        )

        self.assertEqual(outcome.status, "scan_failed")
        self.assertEqual(outcome.overall_scan_status, "error")
        self.assertFalse(self.storage.package_exists(f"live/{listing_id}/{version}"))
        self.assertIn("scan timed out", outcome.error_message)

        db_record = self.repo.get_listing_version(listing_id, version)
        self.assertEqual(db_record["status"], "scan_failed")

        # Scratch directory cleaned up
        self.assertFalse(os.path.exists(scratch_dir))

    def test_scanner_exception_fails_closed_and_cleans_scratch(self):
        """Unhandled exception in a scanner -> fail-closed to 'scan_failed', deletes scratch directory."""
        scratch_dir = self._create_scratch_dir(clean=True)
        listing_id = "listing_crash_004"
        version = "v1.0.0"

        def mock_crashing_scanner(path, **kwargs):
            raise MemoryError("Out of memory in scanner engine")

        outcome = process_upload(
            listing_id=listing_id,
            version=version,
            scratch_dir=scratch_dir,
            scanners=[mock_crashing_scanner],
            storage_client=self.storage,
            repository=self.repo,
        )

        # Fail closed
        self.assertEqual(outcome.status, "scan_failed")
        self.assertEqual(outcome.overall_scan_status, "error")
        self.assertIn("MemoryError", outcome.error_message)
        self.assertFalse(self.storage.package_exists(f"live/{listing_id}/{version}"))

        # Scratch directory guaranteed deleted
        self.assertFalse(os.path.exists(scratch_dir), "Scratch directory was not deleted after crash!")

    def test_multi_scanner_result_aggregation_and_count_summing(self):
        """Confirms merge_scan_results merges findings, sums severity counts, and preserves rule IDs."""
        finding1 = _make_finding("AWS_ACCESS_KEY", Severity.CRITICAL, "auth.py")
        finding2 = _make_finding("SLACK_WEBHOOK", Severity.HIGH, "notify.py")
        finding3 = _make_finding("SQL_INJECTION", Severity.CRITICAL, "db.py")  # static analysis finding

        res1 = PackageScanResult(
            status=ContractStatus.FAILED.value,
            findings=[finding1, finding2],
            severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0},
        )
        res2 = PackageScanResult(
            status=ContractStatus.FAILED.value,
            findings=[finding3],
            severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        )

        status, findings, counts, suppressed, errors = merge_scan_results([res1, res2])

        self.assertEqual(status, "failed")
        self.assertEqual(len(findings), 3)
        self.assertEqual({f.rule_id for f in findings}, {"AWS_ACCESS_KEY", "SLACK_WEBHOOK", "SQL_INJECTION"})
        self.assertEqual(counts["critical"], 2)  # 1 + 1
        self.assertEqual(counts["high"], 1)      # 1 + 0
        self.assertEqual(counts["medium"], 0)

    def test_multi_scanner_mixed_pass_fail_cases(self):
        """Exhaustively tests fail-closed aggregation across mixed scanner outcomes:
        - Scanner 1 PASSED, Scanner 2 FAILED -> overall 'failed' -> 'scan_failed'
        - Scanner 1 FAILED, Scanner 2 PASSED -> overall 'failed' -> 'scan_failed'
        - Scanner 1 PASSED, Scanner 2 ERROR  -> overall 'error'  -> 'scan_failed'
        """
        def scanner_pass(path, **kwargs):
            return PackageScanResult(
                status=ContractStatus.PASSED.value,
                findings=[],
                severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            )

        def scanner_fail(path, **kwargs):
            return PackageScanResult(
                status=ContractStatus.FAILED.value,
                findings=[_make_finding("STATIC_AST_EVAL", Severity.HIGH, "main.py")],
                severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0},
            )

        def scanner_error(path, **kwargs):
            return PackageScanResult(
                status=ContractStatus.ERROR.value,
                findings=[],
                severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
                error_message="ScannerInternalError",
            )

        # Case 1: Pass + Fail -> failed
        scratch1 = self._create_scratch_dir()
        out1 = process_upload("list1", "v1", scratch1, scanners=[scanner_pass, scanner_fail], storage_client=self.storage, repository=self.repo)
        self.assertEqual(out1.status, "scan_failed")
        self.assertEqual(out1.overall_scan_status, "failed")
        self.assertEqual(len(out1.findings), 1)
        self.assertEqual(out1.findings[0].rule_id, "STATIC_AST_EVAL")
        self.assertFalse(os.path.exists(scratch1))

        # Case 2: Fail + Pass -> failed
        scratch2 = self._create_scratch_dir()
        out2 = process_upload("list2", "v1", scratch2, scanners=[scanner_fail, scanner_pass], storage_client=self.storage, repository=self.repo)
        self.assertEqual(out2.status, "scan_failed")
        self.assertEqual(out2.overall_scan_status, "failed")
        self.assertFalse(os.path.exists(scratch2))

        # Case 3: Pass + Error -> error (fail-closed)
        scratch3 = self._create_scratch_dir()
        out3 = process_upload("list3", "v1", scratch3, scanners=[scanner_pass, scanner_error], storage_client=self.storage, repository=self.repo)
        self.assertEqual(out3.status, "scan_failed")
        self.assertEqual(out3.overall_scan_status, "error")
        self.assertIn("ScannerInternalError", out3.error_message)
        self.assertFalse(os.path.exists(scratch3))

    def test_scan_outcome_to_dict_contract(self):
        """Confirms ScanOutcome.to_dict() matches the expected seller-facing schema."""
        scratch_dir = self._create_scratch_dir(clean=True)
        outcome = process_upload("listing_dict_test", "v1", scratch_dir)
        
        d = outcome.to_dict()
        self.assertIn("listing_id", d)
        self.assertIn("version", d)
        self.assertIn("status", d)
        self.assertIn("overall_scan_status", d)
        self.assertIn("findings", d)
        self.assertIn("severity_counts", d)
        self.assertIn("storage_location", d)
        self.assertIn("scanner_count", d)
        self.assertEqual(d["status"], "live")
        self.assertEqual(d["scanner_count"], len(DEFAULT_SCANNERS))

    def test_three_scanner_merge_unioned_findings_and_escalated_status(self):
        """Tests that merge_package_results merges secrets + static + cve results.
        
        Verifies unioned findings, exact summed severity counts, and status escalation.
        """
        f_secret = _make_finding("AWS_KEY", Severity.CRITICAL)
        res_secrets = PackageScanResult(
            status="failed",
            findings=[f_secret],
            severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
            metadata=ScanMetadata(duration_seconds=0.01, files_scanned=5, files_skipped=0, scan_history_ran=False),
        )

        f_static = _make_finding("UNSAFE_EXEC", Severity.HIGH)
        res_static = PackageScanResult(
            status="failed",
            findings=[f_static],
            severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0},
            metadata=ScanMetadata(duration_seconds=0.02, files_scanned=5, files_skipped=1, scan_history_ran=False),
        )

        f_cve = _make_finding("CVE-2023-1234", Severity.MEDIUM)
        res_cve = PackageScanResult(
            status="passed",
            findings=[f_cve],
            severity_counts={"critical": 0, "high": 0, "medium": 1, "low": 0},
            metadata=ScanMetadata(duration_seconds=0.03, files_scanned=1, files_skipped=0, scan_history_ran=False),
        )

        combined = merge_package_results(res_secrets, res_static, res_cve)

        # Status escalated to "failed" because of critical/high findings
        self.assertEqual(combined.status, "failed")
        # All 3 findings unioned
        self.assertEqual(len(combined.findings), 3)
        finding_rule_ids = {f.rule_id for f in combined.findings}
        self.assertEqual(finding_rule_ids, {"AWS_KEY", "UNSAFE_EXEC", "CVE-2023-1234"})
        # Summed severity counts
        self.assertEqual(combined.severity_counts["critical"], 1)
        self.assertEqual(combined.severity_counts["high"], 1)
        self.assertEqual(combined.severity_counts["medium"], 1)
        self.assertEqual(combined.severity_counts["low"], 0)
        # Summed metadata
        self.assertEqual(combined.metadata.files_scanned, 11)
        self.assertEqual(combined.metadata.files_skipped, 1)

        # Verify escalation to "error" if one scanner errored
        res_error = PackageScanResult(
            status="error",
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            error_message="OSV.dev API unavailable",
        )
        combined_err = merge_package_results(res_secrets, res_static, res_error)
        self.assertEqual(combined_err.status, "error")
        self.assertIn("OSV.dev API unavailable", combined_err.error_message)

    def test_process_upload_with_real_default_scanners_catches_cve(self):
        """Integration test: exercises real DEFAULT_SCANNERS list to detect a CVE."""
        import json
        from unittest.mock import patch
        from cve_check.osv_client import OSVClient
        from static_analysis.manifests import DeclaredDependency

        scratch_dir = self._create_scratch_dir(clean=True)
        pkg_path = Path(scratch_dir) / "package.json"
        pkg_path.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}), encoding="utf-8")

        mock_vulns = [
            (
                DeclaredDependency("lodash", "4.17.15", True, "npm", str(pkg_path), 2),
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

        with patch.object(OSVClient, "query_dependencies", return_value=mock_vulns):
            # Crucial: do NOT pass scanners= list, rely on real DEFAULT_SCANNERS
            outcome = process_upload(
                "listing_real_default",
                "v1.0",
                scratch_dir,
                storage_client=self.storage,
                repository=self.repo,
            )

        self.assertEqual(outcome.status, "scan_failed")
        self.assertEqual(outcome.overall_scan_status, "failed")
        self.assertEqual(len(outcome.scanner_results), 3)
        self.assertEqual(len(outcome.scanner_results), len(DEFAULT_SCANNERS))

        # Check CVE finding surfaced in outcome
        cve_findings = [f for f in outcome.findings if "CVE-2020-8203" in getattr(f, "cve_id", "") or "GHSA-p6mc-m468-83gw" in f.rule_id]
        self.assertEqual(len(cve_findings), 1)

        # Verify storage remains in pending, not live
        self.assertTrue(outcome.storage_location.startswith("pending/"))
        self.assertFalse(self.storage.package_exists("live/listing_real_default/v1.0"))


if __name__ == "__main__":
    unittest.main()
