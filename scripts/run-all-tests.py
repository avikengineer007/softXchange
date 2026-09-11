#!/usr/bin/env python3
"""
scripts/run-all-tests.py

Unified test runner executing the complete softXchange test battery across
all microservices, packages, and integration gates in proper process isolation.
"""

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TEST_SUITES = [
    ("Root Integration & Security Gates", ["tests/test_database_migrations.py", "tests/test_production_fail_closed.py", "tests/test_storage_rule.py", "tests/test_shared_backend_parity.py"]),
    ("packages/ml-shared", ["packages/ml-shared/tests"]),
    ("apps/broker", ["apps/broker/tests"]),
    ("apps/buyer-assist", ["apps/buyer-assist/tests"]),
    ("apps/seller-assist", ["apps/seller-assist/tests"]),
    ("apps/auth-service", ["apps/auth-service/tests"]),
    ("apps/listings-service", ["apps/listings-service/tests"]),
    ("apps/payments-service", ["apps/payments-service/tests"]),
    ("apps/scan-service", ["apps/scan-service/tests"]),
    ("apps/web-unified", ["apps/web-unified/tests"]),
    ("Secret Scanner engine", ["Secret Scanner engine/tests"]),
]


def main():
    print("==========================================================")
    print("  softXchange Full Automated Test Battery")
    print("==========================================================\n")

    py_exe = sys.executable
    total_passed = 0
    failures = []
    start_all = time.perf_counter()

    for name, paths in TEST_SUITES:
        print(f"Running [{name}]...", end=" ", flush=True)
        start = time.perf_counter()
        cmd = [py_exe, "-m", "pytest"] + paths + ["-q"]
        result = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        elapsed = round(time.perf_counter() - start, 2)

        if result.returncode == 0:
            output_lines = [l for l in result.stdout.strip().split("\n") if l]
            summary = output_lines[-1] if output_lines else "PASSED"
            print(f"PASSED ({elapsed}s) -> {summary}")
        else:
            print(f"FAILED ({elapsed}s)")
            failures.append((name, result.stdout + "\n" + result.stderr))

    total_time = round(time.perf_counter() - start_all, 2)
    print("\n==========================================================")
    if not failures:
        print(f"  ALL TEST SUITES PASSED ({total_time}s)!")
        print("==========================================================")
        return 0
    else:
        print(f"  {len(failures)} SUITE(S) FAILED ({total_time}s):")
        for name, err in failures:
            print(f"\n--- Failure in {name} ---")
            print(err)
        print("==========================================================")
        return 1


if __name__ == "__main__":
    sys.exit(main())
