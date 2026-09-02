"""Seller-facing status query service and lightweight verification HTTP server.

DEV HARNESS NOTICE:
This HTTP server is a local development and end-to-end verification harness.
It does NOT implement public marketplace authentication (which will be provided
by auth-service via session/JWT tokens) and is intended solely for local pipeline
testing and end-to-end verification.
"""

from dataclasses import dataclass
from enum import Enum
import json
import logging
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

from .contract import ContractStatus
from .intake import IntakePipeline, IntakeSource, ListingStatus, ListingVersion, UploadRecord
from .job_queue import IntakeGateway, JobStatus, PostgresJobQueue, ScanJobWorker
from .service_orchestrator import InMemoryPostgresListingRepository, ListingRepository

logger = logging.getLogger("scan_service.server")


# -----------------------------------------------------------------------------
# Status Collapsing Logic
# -----------------------------------------------------------------------------

VALID_SELLER_STATUSES = {"pending_scan", "live", "scan_failed"}

# Exhaustive mapping of all internal listing and job states to canonical seller states
INTERNAL_STATUS_MAPPING: Dict[str, str] = {
    # Pending / in-flight states -> "pending_scan"
    ListingStatus.PENDING_SCAN.value: "pending_scan",
    ListingStatus.SCANNING.value: "pending_scan",
    JobStatus.QUEUED.value: "pending_scan",
    JobStatus.PROCESSING.value: "pending_scan",
    "queued": "pending_scan",
    "processing": "pending_scan",
    "pending_scan": "pending_scan",
    "scanning": "pending_scan",

    # Passed / live states -> "live"
    ListingStatus.PASSED.value: "live",
    "live": "live",
    "passed": "live",

    # Failed / blocked states -> "scan_failed"
    ListingStatus.FAILED.value: "scan_failed",
    ListingStatus.SCAN_FAILED.value: "scan_failed",
    ListingStatus.ERROR.value: "scan_failed",
    JobStatus.DEAD.value: "scan_failed",
    JobStatus.FAILED.value: "scan_failed",
    "failed": "scan_failed",
    "scan_failed": "scan_failed",
    "error": "scan_failed",
    "dead": "scan_failed",
}


def collapse_seller_status(internal_status: Union[ListingStatus, JobStatus, str]) -> str:
    """Collapses internal fine-grained engine states into the canonical seller-facing status.
    
    Returns:
        One of: 'pending_scan', 'live', 'scan_failed'.
        
    Raises:
        ValueError: If an unhandled internal state is encountered (fails loud).
    """
    raw_val = internal_status.value if hasattr(internal_status, "value") else str(internal_status).lower()
    
    if raw_val not in INTERNAL_STATUS_MAPPING:
        logger.critical("Unhandled internal status encountered in status collapsing: %r", internal_status)
        raise ValueError(f"Unhandled internal status cannot be mapped to seller state: {internal_status!r}")
        
    seller_status = INTERNAL_STATUS_MAPPING[raw_val]
    assert seller_status in VALID_SELLER_STATUSES
    return seller_status


# -----------------------------------------------------------------------------
# Seller Status Read Model Service
# -----------------------------------------------------------------------------

class ListingStatusService:
    """Read model query service for seller-facing listing status."""

    def __init__(self, pipeline: IntakePipeline, repository: Optional[ListingRepository] = None):
        self.pipeline = pipeline
        self.repository = repository

    def get_status(self, listing_id: str, version: str) -> Optional[Dict[str, Any]]:
        """Retrieves and formats the seller-facing status for a listing version.
        
        Guarantees:
          - Status is strictly collapsed into 'pending_scan' | 'live' | 'scan_failed'.
          - Findings expose only the pre-redacted snippet from scanner output.
          - Never surfaces internal tokens or secrets.
        """
        # 1. Check database repository if provided
        db_record = None
        if self.repository:
            db_record = self.repository.get_listing_version(listing_id, version)

        # 2. Check pipeline in-memory version store
        key = (listing_id, version)
        pipeline_version: Optional[ListingVersion] = self.pipeline.versions.get(key)

        if not db_record and not pipeline_version:
            return None

        # Determine raw status
        raw_status = "pending_scan"
        storage_location = f"pending/{listing_id}/{version}"
        resolved_commit_sha = None
        error_message = None
        findings: List[Dict[str, Any]] = []
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        if db_record:
            raw_status = db_record.get("status", raw_status)
            storage_location = db_record.get("storage_location", storage_location)
            error_message = db_record.get("error_message")
            scan_res = db_record.get("scan_result", {})
            if isinstance(scan_res, dict):
                findings = scan_res.get("findings", [])
                severity_counts = scan_res.get("severity_counts", severity_counts)

        if pipeline_version:
            # Pipeline object has the authoritative commit SHA and runtime scan result
            if pipeline_version.resolved_commit_sha:
                resolved_commit_sha = pipeline_version.resolved_commit_sha
            if not db_record:
                raw_status = pipeline_version.status.value
                storage_location = pipeline_version.storage_location
                error_message = pipeline_version.error_message
                if pipeline_version.scan_result:
                    sr_dict = pipeline_version.scan_result.to_dict()
                    findings = sr_dict.get("findings", [])
                    severity_counts = sr_dict.get("severity_counts", severity_counts)

        # Collapse internal status to canonical seller state
        seller_status = collapse_seller_status(raw_status)

        # Ensure findings strictly maintain the redacted snippets
        sanitized_findings = [
            {
                "file_path": f.get("file_path"),
                "line_number": f.get("line_number"),
                "rule_id": f.get("rule_id"),
                "rule_name": f.get("rule_name"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "commit_hash": f.get("commit_hash"),
                "redacted_snippet": f.get("redacted_snippet"),
                "description": f.get("description"),
            }
            for f in findings
        ]

        return {
            "listing_id": listing_id,
            "version": version,
            "status": seller_status,
            "storage_location": storage_location,
            "severity_counts": dict(severity_counts),
            "findings": sanitized_findings,
            "resolved_commit_sha": resolved_commit_sha,
            "error_message": error_message,
        }


# -----------------------------------------------------------------------------
# REST Request Handler
# -----------------------------------------------------------------------------

STATUS_PATH_REGEX = re.compile(r"^/api/listings/([^/]+)/versions/([^/]+)/status/?$")


class ScanServiceHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler exposing intake and seller status endpoints."""

    # Injected application context: gateway and status_service
    gateway: Optional[IntakeGateway] = None
    status_service: Optional[ListingStatusService] = None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        match = STATUS_PATH_REGEX.match(parsed.path)
        
        if not match:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})
            return

        listing_id, version = match.group(1), match.group(2)
        if not self.status_service:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Status service not configured"})
            return

        status_data = self.status_service.get_status(listing_id, version)
        if not status_data:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Listing {listing_id} version {version} not found"})
            return

        self._send_json(HTTPStatus.OK, status_data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        
        if parsed.path != "/api/intake/upload":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})
            return

        if not self.gateway:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Gateway not configured"})
            return

        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing JSON request body"})
            return

        try:
            body = json.loads(self.rfile.read(content_len).decode("utf-8"))
        except Exception as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Malformed JSON: {e}"})
            return

        listing_id = body.get("listing_id")
        version_id = body.get("version_id")
        seller_id = body.get("seller_id", "default_seller")
        intake_source = body.get("intake_source")

        if not listing_id or not version_id or not intake_source:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "listing_id, version_id, and intake_source are required"})
            return

        resp = self.gateway.submit_intake_async(
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            intake_source=intake_source,
            archive_path=body.get("archive_path"),
            repo_url=body.get("repo_url"),
            ref=body.get("ref"),
            is_private=body.get("is_private", False),
            scan_kwargs=body.get("scan_kwargs"),
        )

        self._send_json(HTTPStatus.ACCEPTED, resp.to_dict())

    def _send_json(self, status: HTTPStatus, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request log lines during testing
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)


# -----------------------------------------------------------------------------
# Server Application Factory
# -----------------------------------------------------------------------------

@dataclass
class ScanServiceApp:
    """Assembled scan service harness."""
    queue: PostgresJobQueue
    pipeline: IntakePipeline
    gateway: IntakeGateway
    repository: ListingRepository
    status_service: ListingStatusService
    server: ThreadingHTTPServer
    server_url: str

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def create_scan_service_app(
    host: str = "127.0.0.1",
    port: int = 0,
    db_path: str = ":memory:",
    pipeline: Optional[IntakePipeline] = None,
    repository: Optional[ListingRepository] = None,
) -> ScanServiceApp:
    """Factory creating an assembled scan service harness with HTTP server."""
    repo = repository or InMemoryPostgresListingRepository()
    pipe = pipeline or IntakePipeline()
    queue = PostgresJobQueue(db_path=db_path)
    gateway = IntakeGateway(pipeline=pipe, queue=queue)
    status_svc = ListingStatusService(pipeline=pipe, repository=repo)

    # Bind handler context
    class BoundHandler(ScanServiceHTTPHandler):
        pass

    BoundHandler.gateway = gateway
    BoundHandler.status_service = status_svc

    server = ThreadingHTTPServer((host, port), BoundHandler)
    assigned_port = server.server_address[1]
    server_url = f"http://{host}:{assigned_port}"

    return ScanServiceApp(
        queue=queue,
        pipeline=pipe,
        gateway=gateway,
        repository=repo,
        status_service=status_svc,
        server=server,
        server_url=server_url,
    )
