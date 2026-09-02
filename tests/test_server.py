"""Unit tests for seller status endpoint, status collapsing, and HTTP server handler."""

import json
import os
import shutil
import tempfile
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict

from secrets_scanner.contract import ContractStatus, PackageScanResult
from secrets_scanner.intake import IntakePipeline, IntakeSource, ListingStatus, ListingVersion
from secrets_scanner.models import Confidence, Finding, Severity
from secrets_scanner.server import (
    ListingStatusService,
    collapse_seller_status,
    create_scan_service_app,
)
from secrets_scanner.service_orchestrator import InMemoryPostgresListingRepository


class TestServerAndStatus(unittest.TestCase):

    def setUp(self):
        self.pipeline = IntakePipeline()
        self.repository = InMemoryPostgresListingRepository()
        self.status_service = ListingStatusService(pipeline=self.pipeline, repository=self.repository)

    def test_status_collapsing_exhaustive(self):
        """Confirms every known engine status maps to a valid seller status, and unknown fails loud."""
        expected_mappings = {
            "pending_scan": "pending_scan",
            "scanning": "pending_scan",
            "queued": "pending_scan",
            "processing": "pending_scan",
            "live": "live",
            "passed": "live",
            "failed": "scan_failed",
            "scan_failed": "scan_failed",
            "error": "scan_failed",
            "dead": "scan_failed",
        }

        for internal_val, expected_seller_val in expected_mappings.items():
            with self.subTest(status=internal_val):
                self.assertEqual(collapse_seller_status(internal_val), expected_seller_val)

        # Fails loud on unhandled status
        with self.assertRaises(ValueError):
            collapse_seller_status("some_unhandled_future_status_xyz")

    def test_get_status_live_formatting(self):
        """Passed scan correctly maps to 'live' with 0 findings and live storage location."""
        self.repository.update_status_and_results(
            listing_id="list_pass",
            version="v1.0",
            status="live",
            scan_result={"findings": [], "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}},
            storage_location="live/list_pass/v1.0/",
        )

        res = self.status_service.get_status("list_pass", "v1.0")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "live")
        self.assertEqual(res["storage_location"], "live/list_pass/v1.0/")
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["severity_counts"]["critical"], 0)

    def test_get_status_failed_preserves_redacted_snippets(self):
        """Failed scan surfaces only redacted snippets and never leaks raw tokens."""
        finding = {
            "file_path": "auth.py",
            "line_number": 42,
            "rule_id": "AWS_ACCESS_KEY",
            "rule_name": "AWS Access Key",
            "severity": "critical",
            "confidence": "high",
            "redacted_snippet": "AWS_KEY = 'AKIA****************'",
            "description": "AWS access key id",
        }
        self.repository.update_status_and_results(
            listing_id="list_fail",
            version="v1.0",
            status="scan_failed",
            scan_result={"findings": [finding], "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}},
            storage_location="pending/list_fail/v1.0/",
        )

        res = self.status_service.get_status("list_fail", "v1.0")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "scan_failed")
        self.assertEqual(res["storage_location"], "pending/list_fail/v1.0/")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["redacted_snippet"], "AWS_KEY = 'AKIA****************'")
        self.assertEqual(res["severity_counts"]["critical"], 1)

    def test_get_status_not_found(self):
        """Non-existent listing returns None."""
        self.assertIsNone(self.status_service.get_status("nonexistent_id", "v1"))

    def test_http_endpoints_end_to_end(self):
        """Tests HTTP server GET status and POST upload endpoints."""
        app = create_scan_service_app(host="127.0.0.1", port=0)
        import threading
        server_thread = threading.Thread(target=app.server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # 1. POST /api/intake/upload
            payload = {
                "listing_id": "list_http_test",
                "version_id": "v1.0",
                "seller_id": "seller_abc",
                "intake_source": "file_upload",
                "archive_path": "test.zip",
            }
            req = urllib.request.Request(
                f"{app.server_url}/api/intake/upload",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 202)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["status"], "pending_scan")
                self.assertTrue(data["job_id"].startswith("job_"))

            # 2. GET /api/listings/<id>/versions/<ver>/status -> initially pending_scan
            status_url = f"{app.server_url}/api/listings/list_http_test/versions/v1.0/status"
            with urllib.request.urlopen(status_url) as resp:
                self.assertEqual(resp.status, 200)
                s_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(s_data["status"], "pending_scan")
                self.assertEqual(s_data["listing_id"], "list_http_test")

            # 3. GET unknown listing -> 404
            unknown_url = f"{app.server_url}/api/listings/unknown_xyz/versions/v1.0/status"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(unknown_url)
            self.assertEqual(ctx.exception.code, 404)

        finally:
            app.shutdown()


if __name__ == "__main__":
    unittest.main()
