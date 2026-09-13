#!/usr/bin/env python3
"""
scripts/migrate.py

Unified migration manager for softXchange.
Runs Alembic migrations forward (upgrade head) or backward (downgrade base)
across all four stateful service databases:
- softxchange_auth (auth-service)
- softxchange_listings (listings-service)
- softxchange_payments (payments-service)
- softxchange_scan (scan-service)
"""

import argparse
import os
import sys
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

REPO_ROOT = Path(__file__).resolve().parent.parent

SERVICES = [
    {
        "name": "auth-service",
        "ini": REPO_ROOT / "apps" / "auth-service" / "alembic.ini",
        "script": REPO_ROOT / "apps" / "auth-service" / "alembic",
        "db_env": "DATABASE_URL_AUTH",
        "default_db": "postgresql://softxchange:softxchange_dev_pass@localhost:5432/softxchange_auth",
        "tables": ["users", "refresh_tokens", "seller_profiles", "verification_tokens", "admin_provision_audit_logs", "admin_provisioning_state", "notifications", "seller_github_connections"],
    },
    {
        "name": "listings-service",
        "ini": REPO_ROOT / "apps" / "listings-service" / "alembic.ini",
        "script": REPO_ROOT / "apps" / "listings-service" / "alembic",
        "db_env": "DATABASE_URL_LISTINGS",
        "default_db": "postgresql://softxchange:softxchange_dev_pass@localhost:5432/softxchange_listings",
        "tables": ["listings", "listing_versions", "buyer_questions", "buyer_search_events", "listing_embeddings", "listing_reviews", "saved_listings"],
    },
    {
        "name": "payments-service",
        "ini": REPO_ROOT / "apps" / "payments-service" / "alembic.ini",
        "script": REPO_ROOT / "apps" / "payments-service" / "alembic",
        "db_env": "DATABASE_URL_PAYMENTS",
        "default_db": "postgresql://softxchange:softxchange_dev_pass@localhost:5432/softxchange_payments",
        "tables": ["orders", "entitlements", "seller_payment_profiles"],
    },
    {
        "name": "scan-service",
        "ini": REPO_ROOT / "apps" / "scan-service" / "alembic.ini",
        "script": REPO_ROOT / "apps" / "scan-service" / "alembic",
        "db_env": "DATABASE_URL_SCAN",
        "default_db": "postgresql://softxchange:softxchange_dev_pass@localhost:5432/softxchange_scan",
        "tables": ["scan_jobs"],
    },
]


def get_db_url(svc: dict, target_service: str = None) -> str:
    # 1. Check specific svc env var
    url = os.environ.get(svc["db_env"])
    if url:
        return url
    # 2. Check general DATABASE_URL only if targeting a single service
    if target_service is not None:
        url = os.environ.get("DATABASE_URL")
        if url:
            return url
    # 3. Default to localhost postgres
    return svc["default_db"]


def run_command(action: str, target_service: str = None, revision: str = None):
    print("==========================================================")
    print(f"  softXchange Database Migrations: {action.upper()}")
    print("==========================================================\n")

    services = [s for s in SERVICES if target_service is None or s["name"] == target_service]
    if not services:
        print(f"Error: Unknown service '{target_service}'")
        sys.exit(1)

    for svc in services:
        name = svc["name"]
        db_url = get_db_url(svc, target_service)
        print(f"[{name}] Target: {db_url.split('@')[-1] if '@' in db_url else db_url}")

        cfg = Config(str(svc["ini"]))
        cfg.set_main_option("script_location", str(svc["script"]))
        cfg.set_main_option("sqlalchemy.url", db_url)
        os.environ["DATABASE_URL"] = db_url

        try:
            if action == "upgrade":
                rev = revision or "head"
                print(f"  -> Upgrading to '{rev}'...", end=" ", flush=True)
                command.upgrade(cfg, rev)
                print("DONE")

                # Verify tables exist
                engine = create_engine(db_url)
                inspector = inspect(engine)
                present = set(inspector.get_table_names())
                missing = [t for t in svc["tables"] if t not in present]
                if missing:
                    print(f"  [WARNING] Expected tables missing: {missing}")
                else:
                    print(f"  [VERIFIED] All {len(svc['tables'])} expected tables present.")

            elif action == "downgrade":
                rev = revision or "base"
                print(f"  -> Downgrading to '{rev}'...", end=" ", flush=True)
                command.downgrade(cfg, rev)
                print("DONE")

                engine = create_engine(db_url)
                inspector = inspect(engine)
                present = [t for t in inspector.get_table_names() if t != "alembic_version"]
                if present:
                    print(f"  [WARNING] Tables still remaining: {present}")
                else:
                    print("  [VERIFIED] Clean rollback: 0 orphan application tables remain.")

            elif action == "status":
                print("  -> Current heads/revisions:")
                command.current(cfg, verbose=True)

        except Exception as e:
            print(f"FAILED: {e}")
            sys.exit(1)
        print()

    print("==========================================================")
    print("  MIGRATION OPERATION COMPLETED SUCCESSFULLY")
    print("==========================================================\n")


def main():
    parser = argparse.ArgumentParser(description="softXchange Alembic Migration Manager")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # upgrade
    up_p = subparsers.add_parser("upgrade", help="Run migrations forward")
    up_p.add_argument("--service", "-s", help="Specific service name (e.g. auth-service)")
    up_p.add_argument("--revision", "-r", default="head", help="Revision target (default: head)")

    # downgrade
    down_p = subparsers.add_parser("downgrade", help="Run migrations backward (rollback)")
    down_p.add_argument("--service", "-s", help="Specific service name (e.g. auth-service)")
    down_p.add_argument("--revision", "-r", default="base", help="Revision target (default: base)")

    # status
    stat_p = subparsers.add_parser("status", help="Check current migration revision")
    stat_p.add_argument("--service", "-s", help="Specific service name (e.g. auth-service)")

    args = parser.parse_args()
    run_command(args.action, target_service=getattr(args, "service", None), revision=getattr(args, "revision", None))


if __name__ == "__main__":
    main()
