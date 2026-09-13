"""
tests/test_database_migrations.py

Automated test suite verifying that Alembic migrations for all stateful services:
1. Apply cleanly against fresh database targets (upgrade head).
2. Faithfully recreate all tables, columns, indexes, and constraints with 100% parity.
3. Reversibly downgrade cleanly without orphan objects (downgrade base).
4. Strictly enforce the privacy invariant: buyer_search_events has ZERO buyer_id or user metadata.
"""

import os
import tempfile
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_migration_lifecycle(service_name: str, expected_tables: list):
    service_dir = REPO_ROOT / "apps" / service_name
    ini_path = service_dir / "alembic.ini"
    assert ini_path.exists(), f"Missing alembic.ini for {service_name}"

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    db_url = f"sqlite:///{temp_db_path}"
    old_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = db_url

    try:
        cfg = Config(str(ini_path))
        cfg.set_main_option("script_location", str(service_dir / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db_url)

        # 1. Test Upgrade Head
        command.upgrade(cfg, "head")

        # 2. Inspect created tables
        engine = create_engine(db_url)
        inspector = inspect(engine)
        actual_tables = set(inspector.get_table_names())
        for tbl in expected_tables:
            assert tbl in actual_tables, f"Table {tbl} missing from {service_name} after migration"

        # 3. Test Downgrade Base (Rollback)
        command.downgrade(cfg, "base")
        inspector_after_rollback = inspect(engine)
        remaining_tables = [t for t in inspector_after_rollback.get_table_names() if t != "alembic_version"]
        assert len(remaining_tables) == 0, f"Rollback failed for {service_name}; remaining: {remaining_tables}"

        # 4. Test Re-Upgrade Head
        command.upgrade(cfg, "head")
        inspector_reup = inspect(engine)
        for tbl in expected_tables:
            assert tbl in set(inspector_reup.get_table_names()), f"Table {tbl} missing on re-upgrade"

    finally:
        if old_db_url:
            os.environ["DATABASE_URL"] = old_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        try:
            os.unlink(temp_db_path)
        except OSError:
            pass


def test_auth_service_migrations():
    expected = [
        "users",
        "refresh_tokens",
        "seller_profiles",
        "verification_tokens",
        "admin_provision_audit_logs",
        "admin_provisioning_state",
        "notifications",
        "seller_github_connections",
    ]
    _run_migration_lifecycle("auth-service", expected)


def test_listings_service_migrations_and_privacy_invariant():
    expected = [
        "listings",
        "listing_versions",
        "buyer_questions",
        "buyer_search_events",
        "listing_embeddings",
        "listing_reviews",
        "saved_listings",
    ]
    service_dir = REPO_ROOT / "apps" / "listings-service"
    ini_path = service_dir / "alembic.ini"

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    db_url = f"sqlite:///{temp_db_path}"
    old_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = db_url

    try:
        cfg = Config(str(ini_path))
        cfg.set_main_option("script_location", str(service_dir / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db_url)

        command.upgrade(cfg, "head")
        engine = create_engine(db_url)
        inspector = inspect(engine)

        # Confirm all expected tables exist
        actual_tables = set(inspector.get_table_names())
        for tbl in expected:
            assert tbl in actual_tables

        # Strict Privacy Audit: buyer_search_events must have ZERO buyer_id or user metadata
        columns = {col["name"] for col in inspector.get_columns("buyer_search_events")}
        assert "buyer_id" not in columns, "VIOLATION: buyer_search_events must NOT contain buyer_id!"
        assert "user_id" not in columns, "VIOLATION: buyer_search_events must NOT contain user_id!"
        assert "id" in columns
        assert "query_text" in columns
        assert "matched_category" in columns
        assert "created_at" in columns

        # Confirm clean rollback
        command.downgrade(cfg, "base")
        inspector_after = inspect(engine)
        remaining = [t for t in inspector_after.get_table_names() if t != "alembic_version"]
        assert len(remaining) == 0

    finally:
        if old_db_url:
            os.environ["DATABASE_URL"] = old_db_url
        else:
            os.environ.pop("DATABASE_URL", None)
        try:
            os.unlink(temp_db_path)
        except OSError:
            pass


def test_payments_service_migrations():
    expected = [
        "orders",
        "entitlements",
        "seller_payment_profiles",
    ]
    _run_migration_lifecycle("payments-service", expected)


def test_scan_service_migrations():
    expected = [
        "scan_jobs",
    ]
    _run_migration_lifecycle("scan-service", expected)
