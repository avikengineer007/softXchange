"""End-to-end seller verification CLI tool for scan-service.

Runs live asynchronous intake submissions against the scan-service HTTP server,
polls the seller-facing status endpoint until resolution, and verifies pipeline outcomes:
  1. Known-bad secret package -> lands on 'scan_failed', stays in pending/, never live/
  2. Clean package -> lands on 'live', promoted to live/
  3. GitHub URL repository -> clones, pins commit SHA, audits history, lands on 'live'

Usage:
    python demo_seller_verification.py
"""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict

from secrets_scanner.intake import IntakePipeline
from secrets_scanner.job_queue import ScanJobWorker
from secrets_scanner.server import create_scan_service_app


def _init_local_repo(repo_dir: str) -> str:
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "SellerTester"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "seller@example.com"], cwd=repo_dir, check=True)
    
    file_path = os.path.join(repo_dir, "service.py")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("# Clean production service\ndef run():\n    return 'ok'\n")
        
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial clean release"], cwd=repo_dir, check=True, capture_output=True)
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True)
    return res.stdout.strip()


def poll_status(server_url: str, listing_id: str, version_id: str, timeout_seconds: float = 30.0) -> Dict[str, Any]:
    """Polls the GET status endpoint until status is no longer 'pending_scan'."""
    url = f"{server_url}/api/listings/{listing_id}/versions/{version_id}/status"
    start_time = time.monotonic()
    
    while time.monotonic() - start_time < timeout_seconds:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    status = data.get("status")
                    if status != "pending_scan":
                        return data
        except Exception:
            pass
        time.sleep(0.5)
        
    raise TimeoutError(f"Polling status for {listing_id} {version_id} timed out after {timeout_seconds:.1f}s")


def main():
    print("=" * 70)
    print("SCAN-SERVICE SELLER END-TO-END VERIFICATION TOOL")
    print("=" * 70)

    temp_root = tempfile.mkdtemp(prefix="seller_demo_")

    try:
        # 1. Start assembled scan service app with background worker
        print("\n[+] Starting in-process scan service HTTP harness...")
        pipeline = IntakePipeline()
        app = create_scan_service_app(host="127.0.0.1", port=0, pipeline=pipeline)
        
        # Start background worker loop
        stop_worker = threading.Event()
        worker = ScanJobWorker(queue=app.queue, pipeline=app.pipeline, heartbeat_interval_seconds=1.0)
        
        def worker_loop():
            while not stop_worker.is_set():
                job = worker.process_one_job()
                if not job:
                    time.sleep(0.2)

        worker_thread = threading.Thread(target=worker_loop, daemon=True)
        worker_thread.start()

        # Start HTTP server thread
        server_thread = threading.Thread(target=app.server.serve_forever, daemon=True)
        server_thread.start()
        print(f"[*] HTTP Server listening at {app.server_url}")

        # ---------------------------------------------------------------------
        # SCENARIO 1: Known-bad secret file upload
        # ---------------------------------------------------------------------
        print("\n" + "-" * 70)
        print("SCENARIO 1: Upload package containing known-bad secret (AWS key)")
        print("-" * 70)

        bad_zip = os.path.join(temp_root, "bad_secret.zip")
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("app/config.py", 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')

        upload_payload = {
            "listing_id": "listing_bad_secret",
            "version_id": "v1.0",
            "seller_id": "seller_demo",
            "intake_source": "file_upload",
            "archive_path": bad_zip,
        }

        req = urllib.request.Request(
            f"{app.server_url}/api/intake/upload",
            data=json.dumps(upload_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            initial_resp = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Intake API response: HTTP {resp.status}")
            print(f"    Status:  {initial_resp.get('status')}")
            print(f"    Message: {initial_resp.get('message')}")
            print(f"    Job ID:  {initial_resp.get('job_id')}")

        print("[*] Polling seller status endpoint until scan finishes...")
        res_bad = poll_status(app.server_url, "listing_bad_secret", "v1.0")

        print("\n[RESULT] Final Seller Status:")
        print(f"    Status:           {res_bad['status']}")
        print(f"    Storage Location: {res_bad['storage_location']}")
        print(f"    Severity Counts:  {res_bad['severity_counts']}")
        print(f"    Findings Count:   {len(res_bad['findings'])}")
        
        for idx, f in enumerate(res_bad['findings'], 1):
            print(f"      [{idx}] {f['rule_id']} in {f['file_path']}:{f['line_number']}")
            print(f"          Snippet: {f['redacted_snippet']}")

        # Assertions
        assert res_bad["status"] == "scan_failed", f"Expected scan_failed, got {res_bad['status']}"
        assert not res_bad["storage_location"].startswith("live/"), "SECURITY BREACH: Malicious package reached live/!"
        assert res_bad["storage_location"].startswith("pending/"), "Expected package in pending/"
        assert len(res_bad["findings"]) >= 1, "Expected at least 1 finding"
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(res_bad), "LEAK: Raw unredacted token exposed in response!"
        print("\n>>> CONFIRMED: Bad secret package landed on 'scan_failed' and NEVER reached live/.")

        # ---------------------------------------------------------------------
        # SCENARIO 2: Clean file upload
        # ---------------------------------------------------------------------
        print("\n" + "-" * 70)
        print("SCENARIO 2: Upload clean package")
        print("-" * 70)

        clean_zip = os.path.join(temp_root, "clean_pkg.zip")
        with zipfile.ZipFile(clean_zip, "w") as zf:
            zf.writestr("main.py", 'print("Hello from verified marketplace package")\n')

        clean_payload = {
            "listing_id": "listing_clean",
            "version_id": "v1.0",
            "seller_id": "seller_demo",
            "intake_source": "file_upload",
            "archive_path": clean_zip,
        }

        req = urllib.request.Request(
            f"{app.server_url}/api/intake/upload",
            data=json.dumps(clean_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            initial_resp = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Intake API response: HTTP {resp.status} (Status: {initial_resp.get('status')})")

        print("[*] Polling seller status endpoint until scan finishes...")
        res_clean = poll_status(app.server_url, "listing_clean", "v1.0")

        print("\n[RESULT] Final Seller Status:")
        print(f"    Status:           {res_clean['status']}")
        print(f"    Storage Location: {res_clean['storage_location']}")
        print(f"    Severity Counts:  {res_clean['severity_counts']}")
        print(f"    Findings Count:   {len(res_clean['findings'])}")

        # Assertions
        assert res_clean["status"] == "live", f"Expected live, got {res_clean['status']}"
        assert res_clean["storage_location"].startswith("live/"), "Expected live storage location!"
        assert len(res_clean["findings"]) == 0, "Expected 0 findings"
        print("\n>>> CONFIRMED: Clean package promoted to 'live' object storage.")

        # ---------------------------------------------------------------------
        # SCENARIO 3: Clean GitHub URL Repository Intake
        # ---------------------------------------------------------------------
        print("\n" + "-" * 70)
        print("SCENARIO 3: GitHub repository URL intake with commit SHA pinning")
        print("-" * 70)

        git_dir = os.path.join(temp_root, "local_git_remote")
        os.makedirs(git_dir, exist_ok=True)
        expected_sha = _init_local_repo(git_dir)

        # Mock safe_clone_github_repo to clone from our local git directory
        orig_clone = None
        def mock_clone(repo_url, target_dir, ref=None, auth_token=None, timeout_seconds=30.0, **kwargs):
            shutil.copytree(git_dir, target_dir, dirs_exist_ok=True)
            res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True)
            return res.stdout.strip()

        # Monkey-patch safe_clone_github_repo in pipeline
        import secrets_scanner.intake
        orig_clone = secrets_scanner.intake.safe_clone_github_repo
        secrets_scanner.intake.safe_clone_github_repo = mock_clone

        git_payload = {
            "listing_id": "listing_github_tool",
            "version_id": "v1.0",
            "seller_id": "seller_demo",
            "intake_source": "github_url",
            "repo_url": "https://github.com/corp/open-tool",
        }

        req = urllib.request.Request(
            f"{app.server_url}/api/intake/upload",
            data=json.dumps(git_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            initial_resp = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Intake API response: HTTP {resp.status} (Status: {initial_resp.get('status')})")

        print("[*] Polling seller status endpoint until git scan finishes...")
        res_git = poll_status(app.server_url, "listing_github_tool", "v1.0")

        print("\n[RESULT] Final Seller Status:")
        print(f"    Status:           {res_git['status']}")
        print(f"    Storage Location: {res_git['storage_location']}")
        print(f"    Pinned Commit SHA:{res_git['resolved_commit_sha']}")
        print(f"    Findings Count:   {len(res_git['findings'])}")

        assert res_git["status"] == "live", f"Expected live, got {res_git['status']}"
        assert res_git["resolved_commit_sha"] == expected_sha, "SHA mismatch!"
        assert res_git["storage_location"].startswith("live/"), "Expected live storage!"
        print("\n>>> CONFIRMED: GitHub repository cloned, SHA pinned, and promoted to 'live'.")

        # ---------------------------------------------------------------------
        # SCENARIO 4: Upload package triggering BOTH secrets and static analysis
        # ---------------------------------------------------------------------
        print("\n" + "-" * 70)
        print("SCENARIO 4: Upload package with BOTH secrets and static-analysis violations")
        print("-" * 70)

        dual_zip = os.path.join(temp_root, "dual_violations.zip")
        with zipfile.ZipFile(dual_zip, "w") as zf:
            zf.writestr("app/auth.py", 'SLACK_TOKEN = "' + 'xoxb-' + '123456789012-1234567890123-abcdefghijklmnopqrstuvwx"\n')
            zf.writestr("package.json", '{\n  "name": "seller-pkg",\n  "version": "1.0.0",\n  "dependencies": {\n    "crossenv": "1.0.0"\n  }\n}\n')

        dual_payload = {
            "listing_id": "listing_dual_violations",
            "version_id": "v1.0",
            "seller_id": "seller_demo",
            "intake_source": "file_upload",
            "archive_path": dual_zip,
        }

        req = urllib.request.Request(
            f"{app.server_url}/api/intake/upload",
            data=json.dumps(dual_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            initial_resp = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Intake API response: HTTP {resp.status} (Status: {initial_resp.get('status')})")

        print("[*] Polling seller status endpoint until multi-scanner finishes...")
        res_dual = poll_status(app.server_url, "listing_dual_violations", "v1.0")

        print("\n[RESULT] Final Seller Status:")
        print(f"    Status:           {res_dual['status']}")
        print(f"    Storage Location: {res_dual['storage_location']}")
        print(f"    Severity Counts:  {res_dual['severity_counts']}")
        print(f"    Findings Count:   {len(res_dual['findings'])}")

        rule_ids = [f['rule_id'] for f in res_dual['findings']]
        for idx, f in enumerate(res_dual['findings'], 1):
            print(f"      [{idx}] {f['rule_id']} in {f['file_path']}:{f['line_number']}")
            print(f"          Snippet: {f['redacted_snippet']}")

        assert res_dual["status"] == "scan_failed", f"Expected scan_failed, got {res_dual['status']}"
        assert not res_dual["storage_location"].startswith("live/"), "SECURITY BREACH: Malicious package reached live/!"
        assert "SLACK_TOKEN" in rule_ids, "Expected secrets scanner to detect SLACK_TOKEN"
        assert "MANIFEST_MALICIOUS_DEPENDENCY" in rule_ids, "Expected static analysis scanner to detect MANIFEST_MALICIOUS_DEPENDENCY"
        print("\n>>> CONFIRMED: Multi-scanner pipeline executed both secrets and static analysis, merging findings.")

        print("\n" + "=" * 70)
        print("ALL 4 END-TO-END SCENARIOS VERIFIED SUCCESSFULLY!")
        print("=" * 70)

    finally:
        stop_worker.set()
        app.shutdown()
        if 'orig_clone' in locals() and orig_clone is not None:
            secrets_scanner.intake.safe_clone_github_repo = orig_clone
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
