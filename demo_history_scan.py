"""Demonstration script for secrets scanner with git commit history scanning."""

import os
import shutil
import subprocess
import sys
import tempfile

def main():
    print("=" * 60)
    print("SECRETS SCANNER - GIT HISTORY DEMO")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as td:
        # 1. Initialize a temporary git repository
        print("\n[1] Initializing temporary git repository...")
        subprocess.run(["git", "init"], cwd=td, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=td, check=True)
        subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=td, check=True)

        # 2. Commit 1: Add a secret
        print("[2] Commit 1: Committing a hardcoded Slack token...")
        auth_file = os.path.join(td, "auth.py")
        with open(auth_file, "w", encoding="utf-8") as f:
            f.write('SLACK_TOKEN = "' + 'xoxb-' + '123456789012-1234567890123-abcdefghijklmnopqrstuvwx"\n')
        subprocess.run(["git", "add", "."], cwd=td, check=True)
        subprocess.run(["git", "commit", "-m", "Add Slack token"], cwd=td, check=True, capture_output=True)

        # 3. Commit 2: Remove the secret (leaving working tree completely clean)
        print("[3] Commit 2: Removing the Slack token from code...")
        with open(auth_file, "w", encoding="utf-8") as f:
            f.write('# clean code without secrets\nos.environ.get("SLACK_TOKEN")\n')
        subprocess.run(["git", "commit", "-am", "Remove Slack token"], cwd=td, check=True, capture_output=True)

        # 4. Standard scan without --scan-history (Working tree is clean -> PASSED)
        print("\n" + "=" * 60)
        print("PASS 1: Standard working-tree scan (scan-history=False)")
        print("Expectation: PASSED (0 findings, because working tree is clean)")
        print("=" * 60)
        subprocess.run([sys.executable, "-m", "secrets_scanner", td])

        # 5. History scan with --scan-history (Commit 1 diff is inspected -> FLAGGED)
        print("\n" + "=" * 60)
        print("PASS 2: History scan (--scan-history)")
        print("Expectation: FLAGGED (catches the secret committed in Commit 1)")
        print("=" * 60)
        subprocess.run([sys.executable, "-m", "secrets_scanner", td, "--scan-history"])

        # 6. JSON output with commit hash
        print("\n" + "=" * 60)
        print("PASS 3: JSON output format with commit_hash attribute")
        print("=" * 60)
        subprocess.run([sys.executable, "-m", "secrets_scanner", td, "--scan-history", "--json"])

if __name__ == "__main__":
    main()
