from contextlib import asynccontextmanager
import io
import logging
import os
import tempfile
import threading
import time
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel

from secrets_scanner.intake import IntakePipeline, IntakeSource
from secrets_scanner.job_queue import IntakeGateway, ScanJobWorker, PostgresJobQueue
from secrets_scanner.service_orchestrator import InMemoryPostgresListingRepository
from secrets_scanner.server import ListingStatusService, collapse_seller_status

logger = logging.getLogger("scan-service")

# Global pipeline, queue, and worker instances
pipeline = IntakePipeline()
repository = InMemoryPostgresListingRepository()
queue = PostgresJobQueue(db_path=":memory:")
gateway = IntakeGateway(queue=queue, pipeline=pipeline)
status_service = ListingStatusService(pipeline=pipeline, repository=repository)
worker = ScanJobWorker(queue=queue, pipeline=pipeline, heartbeat_interval_seconds=1.0)

_stop_worker = threading.Event()
_worker_thread: Optional[threading.Thread] = None


def _worker_loop():
    logger.info("Scan job worker started.")
    while not _stop_worker.is_set():
        try:
            job = worker.process_one_job()
            if not job:
                time.sleep(0.1)
        except Exception as exc:
            logger.error(f"Error in scan worker loop: {exc}", exc_info=True)
            time.sleep(0.5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker_thread
    _stop_worker.clear()
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True)
    _worker_thread.start()
    yield
    _stop_worker.set()


app = FastAPI(
    title="softXchange Scan Service",
    description="Thin wrapper service around secret-scanner-engine for automated security vetting.",
    version="0.1.0",
    lifespan=lifespan,
)


class IntakeRequest(BaseModel):
    listing_id: str
    version: str
    source_type: str = "github"  # "github" or "upload"
    git_url: Optional[str] = None
    package_content: Optional[str] = None  # Base64 or plain text if submitted via JSON


class ScanStatusResponse(BaseModel):
    listing_id: str
    version: str
    scan_status: str  # "pending_scan" | "passed" | "scan_failed"
    scan_job_id: Optional[str] = None
    storage_location: Optional[str] = None
    severity_counts: Dict[str, int] = {}
    findings: List[Dict[str, Any]] = []
    error_message: Optional[str] = None


def _map_seller_status_to_scan_status(seller_status: str) -> str:
    """
    Map internal seller status to listings-service scan status.
    In scan engine, 'live' means the scan passed.
    For listings-service, we map 'live' to 'passed' so listings-service
    can apply the payout gate before making the listing live.
    """
    if seller_status == "live":
        return "passed"
    return seller_status  # "pending_scan" or "scan_failed"


from fastapi import FastAPI, HTTPException, Request, status

@app.post(
    "/intake",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a package or GitHub repository for security scanning",
)
async def submit_intake(request: Request):
    """
    Accepts package uploads or git URLs, queues scan job, and returns job_id.
    Supports both multipart form-data and application/json.
    """
    content_type = request.headers.get("content-type", "")
    target_listing_id: Optional[str] = None
    target_version: Optional[str] = None
    target_source_type: str = "upload"
    target_git_url: Optional[str] = None
    content_bytes: Optional[bytes] = None
    filename: str = "package.zip"

    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if body.get("listing_id") is not None:
            target_listing_id = str(body["listing_id"])
        if body.get("version") is not None:
            target_version = str(body["version"])
        if body.get("source_type") is not None:
            target_source_type = str(body["source_type"])
        if body.get("git_url") is not None:
            target_git_url = str(body["git_url"])
        if body.get("package_content"):
            val = body.get("package_content")
            try:
                import base64
                decoded = base64.b64decode(val)
                if decoded.startswith(b"PK") or decoded.startswith(b"\x1f\x8b") or len(decoded) > 0:
                    content_bytes = decoded
                else:
                    content_bytes = val.encode("utf-8")
            except Exception:
                content_bytes = val.encode("utf-8")
    else:
        try:
            form = await request.form()
            raw_listing = form.get("listing_id")
            if raw_listing is not None and not isinstance(raw_listing, UploadFile):
                target_listing_id = str(raw_listing)
            raw_version = form.get("version")
            if raw_version is not None and not isinstance(raw_version, UploadFile):
                target_version = str(raw_version)
            raw_source = form.get("source_type")
            if raw_source is not None and not isinstance(raw_source, UploadFile):
                target_source_type = str(raw_source)
            raw_git = form.get("git_url")
            if raw_git is not None and not isinstance(raw_git, UploadFile):
                target_git_url = str(raw_git)
            file_obj = form.get("file")
            if file_obj and hasattr(file_obj, "read"):
                content_bytes = await file_obj.read()
                filename = getattr(file_obj, "filename", "package.zip") or "package.zip"
        except Exception:
            pass

    if not target_listing_id or not target_version:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="listing_id and version are required",
        )

    try:
        if target_git_url:
            async_res = gateway.submit_intake_async(
                listing_id=target_listing_id,
                version_id=target_version,
                seller_id="seller-default",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url=target_git_url,
            )
        elif content_bytes is not None:
            temp_dir = tempfile.mkdtemp(prefix="scan_upload_")
            archive_path = os.path.join(temp_dir, filename)
            with open(archive_path, "wb") as f:
                f.write(content_bytes)

            async_res = gateway.submit_intake_async(
                listing_id=target_listing_id,
                version_id=target_version,
                seller_id="seller-default",
                intake_source=IntakeSource.FILE_UPLOAD,
                archive_path=archive_path,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either git_url or file package upload is required",
            )

        return {
            "listing_id": target_listing_id,
            "version": target_version,
            "scan_job_id": async_res.job_id,
            "scan_status": "pending_scan",
        }

    except Exception as exc:
        logger.error(f"Intake submission failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit package for scanning: {str(exc)}",
        )


@app.get(
    "/status/job/{job_id}",
    response_model=ScanStatusResponse,
    summary="Get security scan status by scan_job_id",
)
def get_scan_status_by_job(job_id: str):
    """
    Queries queue and repository by job_id.
    """
    job = queue.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job {job_id} not found",
        )
    return get_scan_status(job.listing_id, job.version_id)


@app.get(
    "/status/{listing_id}/{version}",
    response_model=ScanStatusResponse,
    summary="Get security scan status, severity summary, and redacted findings by listing and version",
)
def get_scan_status(listing_id: str, version: str):
    """
    Queries scanner engine read model by listing_id and version.
    Guarantees findings only expose redacted snippets.
    """
    status_data = status_service.get_status(listing_id, version)
    if not status_data:
        return ScanStatusResponse(
            listing_id=listing_id,
            version=version,
            scan_status="pending_scan",
            severity_counts={},
            findings=[],
        )

    raw_status = status_data.get("status", "pending_scan")
    scan_status = _map_seller_status_to_scan_status(raw_status)

    return ScanStatusResponse(
        listing_id=listing_id,
        version=version,
        scan_status=scan_status,
        storage_location=status_data.get("storage_location"),
        severity_counts=status_data.get("severity_counts", {}),
        findings=status_data.get("findings", []),
        error_message=status_data.get("error_message"),
    )


@app.get("/healthz", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "scan-service",
    }

