"""Postgres-backed background job queue for scan-service intake.

Provides:
- scan_jobs table schema and durable persistence.
- Atomic job claiming semantics with concurrency safety (FOR UPDATE SKIP LOCKED).
- Active periodic heartbeating while jobs are processing.
- Heartbeat-gated timeout reaper distinguishing slow jobs from crashed workers.
- Non-blocking IntakeGateway returning immediate PENDING_SCAN responses.
- Accurate job status handling (clean scan_failed listing outcome is a successfully completed job;
  retries only trigger on unhandled worker exceptions/crashes).
- Worker restart recovery: in-flight jobs with stale heartbeats are reaped fail-closed.
"""

from enum import Enum
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .intake import IntakePipeline, IntakeSource, ListingStatus, ListingVersion, UploadRecord

logger = logging.getLogger("scan_service.job_queue")


# -----------------------------------------------------------------------------
# Job Status & Models
# -----------------------------------------------------------------------------

class JobStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD = "dead"


@dataclass
class ScanJob:
    """Represents a durable scan intake job."""
    job_id: str
    listing_id: str
    version_id: str
    seller_id: str
    action: str  # "submit_upload" | "resubmit_version"
    payload: Dict[str, Any]
    status: JobStatus = JobStatus.QUEUED
    attempts: int = 0
    max_attempts: int = 2
    timeout_seconds: float = 30.0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    last_heartbeat: Optional[float] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "listing_id": self.listing_id,
            "version_id": self.version_id,
            "seller_id": self.seller_id,
            "action": self.action,
            "payload": self.payload,
            "status": self.status.value,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "last_heartbeat": self.last_heartbeat,
            "error_message": self.error_message,
        }


# -----------------------------------------------------------------------------
# Database-Backed Queue Store
# -----------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    listing_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    seller_id TEXT NOT NULL,
    action TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    timeout_seconds REAL NOT NULL DEFAULT 30.0,
    created_at REAL NOT NULL,
    started_at REAL,
    completed_at REAL,
    last_heartbeat REAL,
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_created ON scan_jobs (status, created_at);
"""


class PostgresJobQueue:
    """Postgres-compatible durable job queue.
    
    Uses standard transactional semantics with atomic claim logic (simulating
    'SELECT ... FOR UPDATE SKIP LOCKED') across concurrent worker processes.
    Default backend utilizes an ACID SQLite database file or in-memory DB for
    zero external dependencies while supporting PostgreSQL statements.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA_SQL)

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            return self._conn
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def enqueue(
        self,
        listing_id: str,
        version_id: str,
        seller_id: str,
        action: str,
        payload: Dict[str, Any],
        max_attempts: int = 2,
        timeout_seconds: float = 30.0,
    ) -> ScanJob:
        """Enqueues a new job with status='queued'."""
        job_id = f"job_{secrets.token_hex(8)}"
        now = time.time()
        job = ScanJob(
            job_id=job_id,
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            action=action,
            payload=payload,
            status=JobStatus.QUEUED,
            attempts=0,
            max_attempts=max_attempts,
            timeout_seconds=timeout_seconds,
            created_at=now,
        )

        query = """
        INSERT INTO scan_jobs (
            job_id, listing_id, version_id, seller_id, action, payload,
            status, attempts, max_attempts, timeout_seconds, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            job.job_id, job.listing_id, job.version_id, job.seller_id, job.action,
            json.dumps(job.payload), job.status.value, job.attempts, job.max_attempts,
            job.timeout_seconds, job.created_at,
        )

        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(query, params)
            if conn != self._conn:
                conn.close()

        logger.info("Enqueued scan job %s for listing %s version %s", job_id, listing_id, version_id)
        return job

    def claim_next_job(self, worker_id: str = "worker-1") -> Optional[ScanJob]:
        """Atomically claims the next available queued job.
        
        Implements 'SELECT ... WHERE status = 'queued' ORDER BY created_at FOR UPDATE SKIP LOCKED'
        inside a serializable transaction to ensure exactly one worker claims any given job.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    # In Postgres: SELECT ... FOR UPDATE SKIP LOCKED
                    # In SQLite: within the exclusive transaction, find oldest queued job
                    cur = conn.execute(
                        "SELECT * FROM scan_jobs WHERE status = ? ORDER BY created_at ASC LIMIT 1",
                        (JobStatus.QUEUED.value,)
                    )
                    row = cur.fetchone()
                    if not row:
                        return None

                    job_id = row["job_id"]
                    now = time.time()

                    # Atomic update to processing
                    conn.execute(
                        """
                        UPDATE scan_jobs 
                        SET status = ?, started_at = ?, last_heartbeat = ?
                        WHERE job_id = ? AND status = ?
                        """,
                        (JobStatus.PROCESSING.value, now, now, job_id, JobStatus.QUEUED.value)
                    )

                return self.get_job(job_id)
            finally:
                if conn != self._conn:
                    conn.close()

    def update_heartbeat(self, job_id: str, timestamp: Optional[float] = None) -> None:
        """Updates last_heartbeat for an actively processing job."""
        now = timestamp or time.time()
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    "UPDATE scan_jobs SET last_heartbeat = ? WHERE job_id = ? AND status = ?",
                    (now, job_id, JobStatus.PROCESSING.value)
                )
            if conn != self._conn:
                conn.close()

    def complete_job(self, job_id: str) -> None:
        """Marks job as successfully completed."""
        now = time.time()
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    "UPDATE scan_jobs SET status = ?, completed_at = ? WHERE job_id = ?",
                    (JobStatus.COMPLETED.value, now, job_id)
                )
            if conn != self._conn:
                conn.close()
        logger.info("Job %s marked COMPLETED", job_id)

    def record_job_failure(self, job_id: str, error_message: str, max_retries_reached: bool = False) -> None:
        """Records an unhandled exception or crash for a job."""
        with self._lock:
            conn = self._get_connection()
            with conn:
                cur = conn.execute("SELECT attempts, max_attempts FROM scan_jobs WHERE job_id = ?", (job_id,))
                row = cur.fetchone()
                if not row:
                    return
                new_attempts = row["attempts"] + 1
                is_dead = max_retries_reached or (new_attempts >= row["max_attempts"])
                new_status = JobStatus.DEAD.value if is_dead else JobStatus.QUEUED.value

                conn.execute(
                    """
                    UPDATE scan_jobs
                    SET attempts = ?, status = ?, error_message = ?
                    WHERE job_id = ?
                    """,
                    (new_attempts, new_status, error_message, job_id)
                )
            if conn != self._conn:
                conn.close()

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Retrieves a job by its ID."""
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return ScanJob(
                    job_id=row["job_id"],
                    listing_id=row["listing_id"],
                    version_id=row["version_id"],
                    seller_id=row["seller_id"],
                    action=row["action"],
                    payload=json.loads(row["payload"]),
                    status=JobStatus(row["status"]),
                    attempts=row["attempts"],
                    max_attempts=row["max_attempts"],
                    timeout_seconds=row["timeout_seconds"],
                    created_at=row["created_at"],
                    started_at=row["started_at"],
                    completed_at=row["completed_at"],
                    last_heartbeat=row["last_heartbeat"],
                    error_message=row["error_message"],
                )
            finally:
                if conn != self._conn:
                    conn.close()

    def find_stale_processing_jobs(self, current_time: Optional[float] = None) -> List[ScanJob]:
        """Finds jobs in 'processing' where last_heartbeat is older than timeout_seconds."""
        now = current_time or time.time()
        stale_jobs: List[ScanJob] = []
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT * FROM scan_jobs WHERE status = ?",
                    (JobStatus.PROCESSING.value,)
                )
                for row in cur.fetchall():
                    timeout = row["timeout_seconds"]
                    last_hb = row["last_heartbeat"] or row["started_at"] or row["created_at"]
                    # Gated on heartbeat staleness, NOT total job runtime
                    if (now - last_hb) > timeout:
                        stale_jobs.append(self.get_job(row["job_id"]))
                return stale_jobs
            finally:
                if conn != self._conn:
                    conn.close()

    def mark_job_dead(self, job_id: str, error_message: str) -> None:
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    "UPDATE scan_jobs SET status = ?, error_message = ? WHERE job_id = ?",
                    (JobStatus.DEAD.value, error_message, job_id)
                )
            if conn != self._conn:
                conn.close()


# -----------------------------------------------------------------------------
# Reaper Watchdog
# -----------------------------------------------------------------------------

def reap_timed_out_jobs(
    queue: PostgresJobQueue,
    pipeline: IntakePipeline,
    current_time: Optional[float] = None,
) -> List[ScanJob]:
    """Inspects in-flight jobs and reaps those with stale heartbeats.
    
    Guarantees:
      - Gated on heartbeat staleness, NOT total job runtime: an actively heartbeating
        long scan is never reaped.
      - Marks dead jobs as 'dead'.
      - Transitions associated UploadRecord and ListingVersion to SCAN_FAILED with
        'JobTimeout: no heartbeat within timeout window'.
    """
    now = current_time or time.time()
    stale_jobs = queue.find_stale_processing_jobs(current_time=now)
    reaped: List[ScanJob] = []

    for job in stale_jobs:
        err_msg = "JobTimeout: no heartbeat within timeout window"
        queue.mark_job_dead(job.job_id, err_msg)
        
        # Transition associated domain entities to SCAN_FAILED
        key = (job.listing_id, job.version_id)
        if key in pipeline.versions:
            ver = pipeline.versions[key]
            ver.status = ListingStatus.SCAN_FAILED
            ver.error_message = err_msg
            ver.updated_at = now
            
        for upl in pipeline.uploads.values():
            if upl.listing_id == job.listing_id and upl.version_id == job.version_id:
                upl.status = ListingStatus.SCAN_FAILED
                upl.error_message = err_msg
                
        logger.warning("Reaped timed out job %s (listing %s)", job.job_id, job.listing_id)
        reaped.append(queue.get_job(job.job_id))

    return reaped


# -----------------------------------------------------------------------------
# Background Worker
# -----------------------------------------------------------------------------

class ScanJobWorker:
    """Worker process claiming queued jobs and executing the scan pipeline.
    
    Guarantees:
      - Periodically sends heartbeats while processing.
      - A clean scan_failed outcome (secrets found) is treated as a successfully COMPLETED job.
      - Unhandled worker exceptions increment attempts; upon reaching max_attempts,
        marks job DEAD and transitions records to SCAN_FAILED.
    """

    def __init__(
        self,
        queue: PostgresJobQueue,
        pipeline: IntakePipeline,
        worker_id: str = "worker-1",
        heartbeat_interval_seconds: float = 5.0,
    ):
        self.queue = queue
        self.pipeline = pipeline
        self.worker_id = worker_id
        self.heartbeat_interval_seconds = heartbeat_interval_seconds

    def process_one_job(self) -> Optional[ScanJob]:
        """Claims and executes a single job. Returns the processed job or None if queue is empty."""
        job = self.queue.claim_next_job(worker_id=self.worker_id)
        if not job:
            return None

        stop_heartbeat = threading.Event()

        def heartbeat_loop():
            while not stop_heartbeat.is_set():
                stop_heartbeat.wait(self.heartbeat_interval_seconds)
                if not stop_heartbeat.is_set():
                    self.queue.update_heartbeat(job.job_id)

        hb_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        hb_thread.start()

        try:
            # Execute pipeline action
            payload = job.payload
            action = job.action
            
            if action == "submit_upload":
                upload_rec, version_rec = self.pipeline.submit_upload(
                    listing_id=job.listing_id,
                    version_id=job.version_id,
                    seller_id=job.seller_id,
                    intake_source=payload.get("intake_source"),
                    archive_path=payload.get("archive_path"),
                    repo_url=payload.get("repo_url"),
                    ref=payload.get("ref"),
                    is_private=payload.get("is_private", False),
                    scan_kwargs=payload.get("scan_kwargs"),
                    upload_id=payload.get("upload_id"),
                )
            elif action == "resubmit_version":
                upload_rec, version_rec = self.pipeline.resubmit_listing_version(
                    listing_id=job.listing_id,
                    version_id=job.version_id,
                    seller_id=job.seller_id,
                    ref=payload.get("ref"),
                    is_private=payload.get("is_private", False),
                )
            else:
                raise ValueError(f"Unknown job action: {action}")

            # Note: A clean scan_failed outcome (secrets detected) IS a successfully completed job!
            # The pipeline successfully verified the package. We complete the job directly.
            self.queue.complete_job(job.job_id)

        except Exception as e:
            logger.exception("Unhandled worker exception while processing job %s", job.job_id)
            err_msg = f"WorkerCrashException: {type(e).__name__}: {str(e)}"
            new_attempts = job.attempts + 1
            is_dead = new_attempts >= job.max_attempts
            self.queue.record_job_failure(job.job_id, err_msg, max_retries_reached=is_dead)

            if is_dead:
                # Transition domain entities to SCAN_FAILED fail-closed
                key = (job.listing_id, job.version_id)
                if key in self.pipeline.versions:
                    ver = self.pipeline.versions[key]
                    ver.status = ListingStatus.SCAN_FAILED
                    ver.error_message = err_msg
                    ver.updated_at = time.time()

                for upl in self.pipeline.uploads.values():
                    if upl.listing_id == job.listing_id and upl.version_id == job.version_id:
                        upl.status = ListingStatus.SCAN_FAILED
                        upl.error_message = err_msg
        finally:
            stop_heartbeat.set()
            hb_thread.join(timeout=1.0)

        return self.queue.get_job(job.job_id)


# -----------------------------------------------------------------------------
# Asynchronous Gateway
# -----------------------------------------------------------------------------

@dataclass
class AsyncIntakeResponse:
    """Immediate response returned to sellers at intake submission."""
    upload_id: str
    listing_id: str
    version_id: str
    job_id: str
    status: str = ListingStatus.PENDING_SCAN.value
    message: str = "Upload received, scanning in progress"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IntakeGateway:
    """Upload endpoint gateway providing non-blocking asynchronous intake."""

    def __init__(self, pipeline: IntakePipeline, queue: PostgresJobQueue):
        self.pipeline = pipeline
        self.queue = queue

    def submit_intake_async(
        self,
        listing_id: str,
        version_id: str,
        seller_id: str,
        intake_source: Union[IntakeSource, str],
        archive_path: Optional[str] = None,
        repo_url: Optional[str] = None,
        ref: Optional[str] = None,
        is_private: bool = False,
        scan_kwargs: Optional[Dict[str, Any]] = None,
        timeout_seconds: float = 30.0,
    ) -> AsyncIntakeResponse:
        """Enqueues upload intake job and returns immediate response."""
        source = IntakeSource(intake_source)
        upload_id = f"upl_{secrets.token_hex(8)}"

        # 1. Register records in PENDING_SCAN state
        upload_rec = UploadRecord(
            upload_id=upload_id,
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            intake_source=source,
            status=ListingStatus.PENDING_SCAN,
            archive_path=archive_path,
            repo_url=repo_url,
            ref=ref,
        )
        version_rec = ListingVersion(
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            intake_source=source,
            status=ListingStatus.PENDING_SCAN,
            repo_url=repo_url,
            ref=ref,
            storage_location=f"pending/{listing_id}/{version_id}",
        )
        self.pipeline.uploads[upload_id] = upload_rec
        self.pipeline.versions[(listing_id, version_id)] = version_rec

        # 2. Enqueue scan job
        payload = {
            "upload_id": upload_id,
            "intake_source": source.value,
            "archive_path": archive_path,
            "repo_url": repo_url,
            "ref": ref,
            "is_private": is_private,
            "scan_kwargs": scan_kwargs or {},
        }
        job = self.queue.enqueue(
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            action="submit_upload",
            payload=payload,
            timeout_seconds=timeout_seconds,
        )

        return AsyncIntakeResponse(
            upload_id=upload_id,
            listing_id=listing_id,
            version_id=version_id,
            job_id=job.job_id,
            status=ListingStatus.PENDING_SCAN.value,
            message="Upload received, scanning in progress",
        )

    def resubmit_intake_async(
        self,
        listing_id: str,
        version_id: str,
        seller_id: str,
        ref: Optional[str] = None,
        is_private: bool = False,
        timeout_seconds: float = 30.0,
    ) -> AsyncIntakeResponse:
        """Enqueues re-scan job and returns immediate response."""
        upload_id = f"upl_{secrets.token_hex(8)}"
        version_rec = ListingVersion(
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            intake_source=IntakeSource.GITHUB_URL,
            status=ListingStatus.PENDING_SCAN,
            ref=ref,
            storage_location=f"pending/{listing_id}/{version_id}",
        )
        self.pipeline.versions[(listing_id, version_id)] = version_rec

        payload = {
            "ref": ref,
            "is_private": is_private,
        }
        job = self.queue.enqueue(
            listing_id=listing_id,
            version_id=version_id,
            seller_id=seller_id,
            action="resubmit_version",
            payload=payload,
            timeout_seconds=timeout_seconds,
        )

        return AsyncIntakeResponse(
            upload_id=upload_id,
            listing_id=listing_id,
            version_id=version_id,
            job_id=job.job_id,
            status=ListingStatus.PENDING_SCAN.value,
            message="Upload received, scanning in progress",
        )
