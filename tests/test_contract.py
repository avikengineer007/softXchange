"""Unit tests for the scan-service output contract and scan_package entry point."""

import os
import tempfile
import unittest
from pathlib import Path

from secrets_scanner.contract import (
    ContractStatus,
    PackageScanResult,
    ScanMetadata,
    compute_severity_counts,
    evaluate_contract_status,
)
from secrets_scanner.models import Confidence, Finding, Severity
from secrets_scanner.orchestrator import scan_package


def _make_dummy_finding(severity: Severity, confidence: Confidence, rule_id: str = "TEST_RULE") -> Finding:
    return Finding(
        file_path="src/config.py",
        line_number=10,
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=severity,
        confidence=confidence,
        redacted_snippet="dummy_secret = '*****'",
        description="Test finding description",
        commit_hash="abcdef123456",
    )


class TestOutputContract(unittest.TestCase):

    def test_full_severity_and_confidence_decision_matrix(self):
        """Exhaustively tests the Severity x Confidence decision matrix.
        
        Spec:
        - Critical/High severity AND High confidence -> FAILED
        - All other combinations (including Medium-confidence Critical) -> PASSED (visible without blocking)
        """
        matrix_expectations = [
            # Severity, Confidence, Expected Status
            (Severity.CRITICAL, Confidence.HIGH, ContractStatus.FAILED),
            (Severity.HIGH, Confidence.HIGH, ContractStatus.FAILED),
            # The critical-at-medium-confidence edge case explicitly tested:
            (Severity.CRITICAL, Confidence.MEDIUM, ContractStatus.PASSED),
            (Severity.CRITICAL, Confidence.LOW, ContractStatus.PASSED),
            (Severity.HIGH, Confidence.MEDIUM, ContractStatus.PASSED),
            (Severity.HIGH, Confidence.LOW, ContractStatus.PASSED),
            (Severity.MEDIUM, Confidence.HIGH, ContractStatus.PASSED),
            (Severity.MEDIUM, Confidence.MEDIUM, ContractStatus.PASSED),
            (Severity.MEDIUM, Confidence.LOW, ContractStatus.PASSED),
            (Severity.LOW, Confidence.HIGH, ContractStatus.PASSED),
            (Severity.LOW, Confidence.MEDIUM, ContractStatus.PASSED),
            (Severity.LOW, Confidence.LOW, ContractStatus.PASSED),
        ]

        for severity, confidence, expected_status in matrix_expectations:
            with self.subTest(severity=severity.value, confidence=confidence.value):
                finding = _make_dummy_finding(severity, confidence)
                status = evaluate_contract_status([finding], has_error=False)
                self.assertEqual(status, expected_status.value)

    def test_block_on_medium_confidence_critical_flag(self):
        """Confirms that when block_on_medium_confidence_critical is True,
        a Critical severity finding with Medium confidence triggers FAILED.
        """
        crit_med_finding = _make_dummy_finding(Severity.CRITICAL, Confidence.MEDIUM, "HARDCODED_PASSWORD")
        
        # Default: PASSED (visible without blocking)
        self.assertEqual(
            evaluate_contract_status([crit_med_finding], block_on_medium_confidence_critical=False),
            ContractStatus.PASSED.value,
        )
        
        # With flag enabled: FAILED
        self.assertEqual(
            evaluate_contract_status([crit_med_finding], block_on_medium_confidence_critical=True),
            ContractStatus.FAILED.value,
        )

    def test_error_status_takes_precedence(self):
        """Confirms that any unhandled error resolves to 'error' status,
        regardless of what findings were collected.
        """
        crit_high_finding = _make_dummy_finding(Severity.CRITICAL, Confidence.HIGH)
        status = evaluate_contract_status([crit_high_finding], has_error=True)
        self.assertEqual(status, ContractStatus.ERROR.value)

    def test_empty_findings_resolves_to_passed(self):
        """Confirms 0 findings with no errors resolves to 'passed'."""
        status = evaluate_contract_status([], has_error=False)
        self.assertEqual(status, ContractStatus.PASSED.value)

    def test_severity_count_aggregation(self):
        """Confirms compute_severity_counts aggregates counts across all severities."""
        findings = [
            _make_dummy_finding(Severity.CRITICAL, Confidence.HIGH),
            _make_dummy_finding(Severity.CRITICAL, Confidence.MEDIUM),
            _make_dummy_finding(Severity.HIGH, Confidence.HIGH),
            _make_dummy_finding(Severity.MEDIUM, Confidence.MEDIUM),
            _make_dummy_finding(Severity.LOW, Confidence.LOW),
            _make_dummy_finding(Severity.LOW, Confidence.LOW),
        ]
        counts = compute_severity_counts(findings)
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 2)

    def test_serialization_contract_to_dict(self):
        """Confirms PackageScanResult.to_dict() serializes cleanly according to the JSON contract."""
        finding = _make_dummy_finding(Severity.CRITICAL, Confidence.HIGH)
        metadata = ScanMetadata(
            duration_seconds=0.123456,
            files_scanned=5,
            files_skipped=1,
            scan_history_ran=True,
        )
        result = PackageScanResult(
            status=ContractStatus.FAILED.value,
            findings=[finding],
            severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
            metadata=metadata,
        )
        d = result.to_dict()

        self.assertEqual(d["status"], "failed")
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["severity"], "critical")
        self.assertEqual(d["findings"][0]["confidence"], "high")
        self.assertEqual(d["findings"][0]["commit_hash"], "abcdef123456")
        self.assertEqual(d["severity_counts"]["critical"], 1)
        self.assertEqual(d["metadata"]["duration_seconds"], 0.1235)
        self.assertEqual(d["metadata"]["files_scanned"], 5)
        self.assertTrue(d["metadata"]["scan_history_ran"])

    def test_scan_package_clean_directory(self):
        """Confirms scan_package on a clean directory produces 'passed' status with metadata."""
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "main.py"), "w") as f:
                f.write("print('Clean hello world')\n")

            result = scan_package(td)
            self.assertEqual(result.status, "passed")
            self.assertEqual(len(result.findings), 0)
            self.assertEqual(result.metadata.files_scanned, 1)
            self.assertGreaterEqual(result.metadata.duration_seconds, 0.0)
            self.assertFalse(result.metadata.scan_history_ran)

    def test_scan_package_failing_directory(self):
        """Confirms scan_package on a package with AWS key produces 'failed' status."""
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "auth.py"), "w") as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')

            result = scan_package(td)
            self.assertEqual(result.status, "failed")
            self.assertGreaterEqual(len(result.findings), 1)
            self.assertGreaterEqual(result.severity_counts["critical"], 1)

    def test_scan_package_invalid_directory_returns_error(self):
        """Confirms scan_package returns 'error' status when given a non-existent path."""
        result = scan_package("Z:/non_existent_path_xyz_12345")
        self.assertEqual(result.status, "error")
        self.assertIsNotNone(result.error_message)


if __name__ == "__main__":
    unittest.main()
