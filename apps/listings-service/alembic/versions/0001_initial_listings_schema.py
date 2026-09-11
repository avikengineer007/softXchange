"""Initial listings service schema

Revision ID: 0001_listings_schema
Revises: 
Create Date: 2026-09-12 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_listings_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. listings
    op.create_table(
        "listings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("seller_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=False),
        sa.Column("price_cents", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="draft"),
        sa.Column("status_message", sa.String(length=500), nullable=True),
        sa.Column("current_version_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_listings_seller_id"), "listings", ["seller_id"], unique=False)
    op.create_index(op.f("ix_listings_category"), "listings", ["category"], unique=False)
    op.create_index(op.f("ix_listings_status"), "listings", ["status"], unique=False)

    # 2. listing_versions
    op.create_table(
        "listing_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("version_label", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("scan_status", sa.String(length=32), nullable=False, server_default="pending_scan"),
        sa.Column("scan_job_id", sa.String(length=128), nullable=True),
        sa.Column("storage_location", sa.String(length=255), nullable=True),
        sa.Column("findings_summary", sa.JSON(), nullable=True),
        sa.Column("findings_detail", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["listing_id"], ["listings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_listing_versions_listing_id"), "listing_versions", ["listing_id"], unique=False)
    op.create_index(op.f("ix_listing_versions_scan_status"), "listing_versions", ["scan_status"], unique=False)
    op.create_index(op.f("ix_listing_versions_scan_job_id"), "listing_versions", ["scan_job_id"], unique=False)

    # 3. buyer_questions
    op.create_table(
        "buyer_questions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("buyer_id", sa.String(length=36), nullable=False),
        sa.Column("question_text", sa.String(length=2000), nullable=False),
        sa.Column("seller_response", sa.String(length=2000), nullable=True),
        sa.Column("draft_reply", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("responded_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["listing_id"], ["listings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_buyer_questions_listing_id"), "buyer_questions", ["listing_id"], unique=False)
    op.create_index(op.f("ix_buyer_questions_buyer_id"), "buyer_questions", ["buyer_id"], unique=False)

    # 4. buyer_search_events (ZERO buyer IDs — strict privacy guarantee)
    op.create_table(
        "buyer_search_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("query_text", sa.String(length=500), nullable=False),
        sa.Column("matched_category", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_buyer_search_events_query_text"), "buyer_search_events", ["query_text"], unique=False)
    op.create_index(op.f("ix_buyer_search_events_matched_category"), "buyer_search_events", ["matched_category"], unique=False)
    op.create_index(op.f("ix_buyer_search_events_created_at"), "buyer_search_events", ["created_at"], unique=False)

    # 5. listing_embeddings
    op.create_table(
        "listing_embeddings",
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("version_id", sa.String(length=36), nullable=True),
        sa.Column("embedding", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["listing_id"], ["listings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["version_id"], ["listing_versions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("listing_id"),
    )
    op.create_index(op.f("ix_listing_embeddings_content_hash"), "listing_embeddings", ["content_hash"], unique=False)


def downgrade() -> None:
    op.drop_table("listing_embeddings")
    op.drop_table("buyer_search_events")
    op.drop_table("buyer_questions")
    op.drop_table("listing_versions")
    op.drop_table("listings")
