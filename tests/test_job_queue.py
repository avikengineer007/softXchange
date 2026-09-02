"""Unit and integration tests for Postgres-backed background job queue and worker."""

import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from unittest.mock import patch

from secrets_scanner.intake import (
    GitHubAppCredentialStore,
    IntakePipeline,
    IntakeSource,
    ListingStatus,
    ListingVersion,
    UploadRecord,
)
from secrets_scanner.job_queue import (
    AsyncIntakeResponse,
    IntakeGateway,
    JobStatus,
    PostgresJobQueue,
    ScanJob,
    ScanJobWorker,
    reap_timed_out_jobs,
)


def _init_git_repo(repo_dir: str, add_secret: bool = False) -> str:
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo_dir, check=True)
    
    file_path = os.path.join(repo_dir, "app.py")
    with open(file_path, "w", encoding="utf-8") as f:
        if add_secret:
            f.write('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        else:
            f.write('print("Hello background worker")\n')
            
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
    sha_proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True)
    return sha_proc.stdout.strip()


class TestPostgresJobQueue(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="queue_test_")
        self.db_path = os.path.join(self.temp_dir, "test_jobs.db")
        self.queue = PostgresJobQueue(db_path=self.db_path)
        self.credential_store = GitHubAppCredentialStore()
        self.pipeline = IntakePipeline(credential_store=self.credential_store)
        self.gateway = IntakeGateway(pipeline=self.pipeline, queue=self.queue)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_concurrent_claim_race_for_update_skip_locked(self):
        """Two workers racing to claim a single queued job -> exactly one succeeds, other gets None."""
        job = self.queue.enqueue(
            listing_id="list_race",
            version_id="v1",
            seller_id="seller_1",
            action="submit_upload",
            payload={"intake_source": "file_upload"},
        )

        claimed_jobs = []
        barrier = threading.Barrier(2)

        def worker_attempt(worker_id: str):
            barrier.wait()  # synchronize workers to claim at the exact same instant
            j = self.queue.claim_next_job(worker_id=worker_id)
            if j:
                claimed_jobs.append((worker_id, j.job_id))

        t1 = threading.Thread(target=worker_attempt, args=("worker-A",))
        t2 = threading.Thread(target=worker_attempt, args=("worker-B",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one worker must have claimed the job
        self.assertEqual(len(claimed_jobs), 1)
        self.assertEqual(claimed_jobs[0][1], job.job_id)

        # Queue is now empty for any subsequent claim
        next_job = self.queue.claim_next_job(worker_id="worker-C")
        self.assertIsNone(next_job)

    def test_full_async_flow_file_upload(self):
        """Asynchronous submission for file upload returns immediately, worker processes to PASSED."""
        clean_zip = os.path.join(self.temp_dir, "clean.zip")
        with zipfile.ZipFile(clean_zip, "w") as zf:
            zf.writestr("app.py", 'print("Safe upload")\n')

        # 1. Non-blocking enqueue
        resp = self.gateway.submit_intake_async(
            listing_id="listing_file_async",
            version_id="v1",
            seller_id="seller_1",
            intake_source=IntakeSource.FILE_UPLOAD,
            archive_path=clean_zip,
        )

        self.assertEqual(resp.status, "pending_scan")
        self.assertIn("Upload received", resp.message)
        self.assertTrue(resp.job_id.startswith("job_"))

        # In-memory record starts at PENDING_SCAN
        version_rec = self.pipeline.versions[("listing_file_async", "v1")]
        self.assertEqual(version_rec.status, ListingStatus.PENDING_SCAN)

        # 2. Worker execution
        worker = ScanJobWorker(queue=self.queue, pipeline=self.pipeline)
        processed_job = worker.process_one_job()

        self.assertIsNotNone(processed_job)
        self.assertEqual(processed_job.status, JobStatus.COMPLETED)
        self.assertIsNotNone(processed_job.completed_at)

        # Domain record updated to PASSED
        self.assertEqual(version_rec.status, ListingStatus.PASSED)
        self.assertTrue(version_rec.storage_location.startswith("live/"))

    def test_full_async_flow_github_url(self):
        """Asynchronous submission for GitHub repo returns immediately, worker clones and pins SHA to PASSED."""
        repo_dir = os.path.join(self.temp_dir, "test_repo")
        os.makedirs(repo_dir, exist_ok=True)
        expected_sha = _init_git_repo(repo_dir, add_secret=False)

        def mock_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            shutil.copytree(repo_dir, target_dir, dirs_exist_ok=True)
            res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True)
            return res.stdout.strip()

        with patch("secrets_scanner.intake.safe_clone_github_repo", side_effect=mock_clone):
            # 1. Non-blocking enqueue
            resp = self.gateway.submit_intake_async(
                listing_id="listing_git_async",
                version_id="v1",
                seller_id="seller_1",
                intake_source=IntakeSource.GITHUB_URL,
                repo_url="https://github.com/org/async-tool",
            )
            self.assertEqual(resp.status, "pending_scan")

            # 2. Worker execution
            worker = ScanJobWorker(queue=self.queue, pipeline=self.pipeline)
            processed_job = worker.process_one_job()

            self.assertEqual(processed_job.status, JobStatus.COMPLETED)
            version_rec = self.pipeline.versions[("listing_git_async", "v1")]
            self.assertEqual(version_rec.status, ListingStatus.PASSED)
            self.assertEqual(version_rec.resolved_commit_sha, expected_sha)

    def test_clean_scan_failed_is_completed_job_not_failure(self):
        """A scan finding secrets results in listing FAILED, but the job itself COMPLETED (attempts NOT incremented)."""
        secret_zip = os.path.join(self.temp_dir, "secret.zip")
        with zipfile.ZipFile(secret_zip, "w") as zf:
            zf.writestr("app.py", 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n')

        resp = self.gateway.submit_intake_async(
            listing_id="listing_sec_fail",
            version_id="v1",
            seller_id="seller_1",
            intake_source=IntakeSource.FILE_UPLOAD,
            archive_path=secret_zip,
        )

        worker = ScanJobWorker(queue=self.queue, pipeline=self.pipeline)
        processed_job = worker.process_one_job()

        # Job completed cleanly
        self.assertEqual(processed_job.status, JobStatus.COMPLETED)
        self.assertEqual(processed_job.attempts, 0)

        # Listing record shows FAILED because of detected findings
        version_rec = self.pipeline.versions[("listing_sec_fail", "v1")]
        self.assertEqual(version_rec.status, ListingStatus.FAILED)
        self.assertGreaterEqual(len(version_rec.scan_result.findings), 1)

    def test_unhandled_worker_exception_increments_attempts_and_dies(self):
        """Unhandled worker crash increments attempts; after max_attempts, job becomes DEAD and record SCAN_FAILED."""
        resp = self.gateway.submit_intake_async(
            listing_id="listing_crash_job",
            version_id="v1",
            seller_id="seller_1",
            intake_source=IntakeSource.FILE_UPLOAD,
            archive_path="dummy.zip",
        )

        worker = ScanJobWorker(queue=self.queue, pipeline=self.pipeline)

        with patch.object(self.pipeline, "submit_upload", side_effect=RuntimeError("Worker OOM Crash")):
            # Attempt 1: fails, re-queued
            job_after_1 = worker.process_one_job()
            self.assertIsNotNone(job_after_1)
            self.assertEqual(job_after_1.attempts, 1)
            self.assertEqual(job_after_1.status, JobStatus.QUEUED)

            # Attempt 2: reaches max_attempts (2) -> DEAD
            job_after_2 = worker.process_one_job()
            self.assertIsNotNone(job_after_2)
            self.assertEqual(job_after_2.attempts, 2)
            self.assertEqual(job_after_2.status, JobStatus.DEAD)

        # Fail-closed guarantee: listing record transitioned to SCAN_FAILED
        version_rec = self.pipeline.versions[("listing_crash_job", "v1")]
        self.assertEqual(version_rec.status, ListingStatus.SCAN_FAILED)
        self.assertIn("WorkerCrashException", version_rec.error_message)

    def test_reaper_heartbeat_staleness_vs_total_runtime(self):
        """Reaper gates on heartbeat staleness, NOT total runtime.
        - Stale heartbeat -> marked DEAD and transitions to SCAN_FAILED.
        - Long-running job with active/recent heartbeat -> untouched.
        """
        now = time.time()
        timeout = 30.0

        # Job 1: Long-running (started 100s ago), but heartbeat was updated 2s ago
        job_active = self.queue.enqueue(
            listing_id="list_active",
            version_id="v1",
            seller_id="s1",
            action="submit_upload",
            payload={},
            timeout_seconds=timeout,
        )
        self.queue.claim_next_job()
        self.queue.update_heartbeat(job_active.job_id, timestamp=now - 2.0)

        # Job 2: Started 40s ago, but heartbeat stopped 35s ago (worker crashed)
        job_stale = self.queue.enqueue(
            listing_id="list_stale",
            version_id="v1",
            seller_id="s1",
            action="submit_upload",
            payload={},
            timeout_seconds=timeout,
        )
        self.queue.claim_next_job()
        self.queue.update_heartbeat(job_stale.job_id, timestamp=now - 35.0)

        # Pre-seed version record for list_stale
        self.pipeline.versions[("list_stale", "v1")] = ListingVersion(
            listing_id="list_stale",
            version_id="v1",
            seller_id="s1",
            intake_source=IntakeSource.FILE_UPLOAD,
            status=ListingStatus.SCANNING,
        )

        # Run reaper at time = now
        reaped_jobs = reap_timed_out_jobs(self.queue, self.pipeline, current_time=now)

        self.assertEqual(len(reaped_jobs), 1)
        self.assertEqual(reaped_jobs[0].job_id, job_stale.job_id)
        self.assertEqual(reaped_jobs[0].status, JobStatus.DEAD)

        # Stale listing record transitioned to SCAN_FAILED
        stale_ver = self.pipeline.versions[("list_stale", "v1")]
        self.assertEqual(stale_ver.status, ListingStatus.SCAN_FAILED)
        self.assertIn("JobTimeout", stale_ver.error_message)

        # Active job remains in PROCESSING (not reaped)
        active_job_refreshed = self.queue.get_job(job_active.job_id)
        self.assertEqual(active_job_refreshed.status, JobStatus.PROCESSING)

    def test_process_restart_simulation(self):
        """Simulates worker restart: in-flight processing job with stale heartbeat is cleanly reaped."""
        now = time.time()
        timeout = 30.0

        # Simulate crash before restart: insert job directly into PROCESSING with stale heartbeat
        job = self.queue.enqueue(
            listing_id="list_restart",
            version_id="v1",
            seller_id="s1",
            action="submit_upload",
            payload={},
            timeout_seconds=timeout,
        )
        self.queue.claim_next_job()
        # Set heartbeat in the past (worker process died without updating)
        self.queue.update_heartbeat(job.job_id, timestamp=now - 45.0)

        self.pipeline.versions[("list_restart", "v1")] = ListingVersion(
            listing_id="list_restart",
            version_id="v1",
            seller_id="s1",
            intake_source=IntakeSource.FILE_UPLOAD,
            status=ListingStatus.SCANNING,
        )

        # Restart simulation: fresh worker and reaper run
        reaped = reap_timed_out_jobs(self.queue, self.pipeline, current_time=now)
        self.assertEqual(len(reaped), 1)
        self.assertEqual(reaped[0].job_id, job.job_id)
        self.assertEqual(reaped[0].status, JobStatus.DEAD)

        ver = self.pipeline.versions[("list_restart", "v1")]
        self.assertEqual(ver.status, ListingStatus.SCAN_FAILED)


if __name__ == "__main__":
    unittest.main()
