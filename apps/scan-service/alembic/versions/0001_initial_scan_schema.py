"""Initial scan service schema

Revision ID: 0001_scan_schema
Revises: 
Create Date: 2026-09-12 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_scan_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("version_id", sa.String(length=36), nullable=False),
        sa.Column("seller_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("timeout_seconds", sa.Float(), nullable=False, server_default="30.0"),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("started_at", sa.Float(), nullable=True),
        sa.Column("completed_at", sa.Float(), nullable=True),
        sa.Column("last_heartbeat", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("job_id"),
    )
    op.create_index(op.f("ix_scan_jobs_status_created"), "scan_jobs", ["status", "created_at"], unique=False)
    op.create_index(op.f("ix_scan_jobs_listing_id"), "scan_jobs", ["listing_id"], unique=False)


def downgrade() -> None:
    op.drop_table("scan_jobs")
