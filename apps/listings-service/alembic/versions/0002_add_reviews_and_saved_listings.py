"""Add reviews and saved listings tables

Revision ID: 0002_reviews_and_saved_listings
Revises: 0001_listings_schema
Create Date: 2026-09-13 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002_reviews_and_saved_listings"
down_revision: Union[str, None] = "0001_listings_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. listing_reviews
    op.create_table(
        "listing_reviews",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("listing_version_id", sa.String(length=36), nullable=True),
        sa.Column("buyer_id", sa.String(length=36), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("review_text", sa.String(length=2000), nullable=True),
        sa.Column("is_edited", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["listing_id"], ["listings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("buyer_id", "listing_id", name="uq_buyer_listing_review"),
    )
    op.create_index(op.f("ix_listing_reviews_listing_id"), "listing_reviews", ["listing_id"], unique=False)
    op.create_index(op.f("ix_listing_reviews_buyer_id"), "listing_reviews", ["buyer_id"], unique=False)

    # 2. saved_listings
    op.create_table(
        "saved_listings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("buyer_id", sa.String(length=36), nullable=False),
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["listing_id"], ["listings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("buyer_id", "listing_id", name="uq_buyer_saved_listing"),
    )
    op.create_index(op.f("ix_saved_listings_buyer_id"), "saved_listings", ["buyer_id"], unique=False)
    op.create_index(op.f("ix_saved_listings_listing_id"), "saved_listings", ["listing_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_saved_listings_listing_id"), table_name="saved_listings")
    op.drop_index(op.f("ix_saved_listings_buyer_id"), table_name="saved_listings")
    op.drop_table("saved_listings")

    op.drop_index(op.f("ix_listing_reviews_buyer_id"), table_name="listing_reviews")
    op.drop_index(op.f("ix_listing_reviews_listing_id"), table_name="listing_reviews")
    op.drop_table("listing_reviews")
