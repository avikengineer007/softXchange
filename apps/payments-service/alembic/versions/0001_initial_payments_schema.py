"""Initial payments service schema

Revision ID: 0001_payments_schema
Revises: 
Create Date: 2026-09-12 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_payments_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. orders
    op.create_table(
        "orders",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("listing_id", sa.String(length=36), nullable=False),
        sa.Column("listing_version_id", sa.String(length=36), nullable=False),
        sa.Column("buyer_id", sa.String(length=36), nullable=False),
        sa.Column("seller_id", sa.String(length=36), nullable=False),
        sa.Column("amount_cents", sa.Integer(), nullable=False),
        sa.Column("platform_fee_cents", sa.Integer(), nullable=False),
        sa.Column("seller_payout_cents", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending_payment"),
        sa.Column("hold_status", sa.String(length=32), nullable=False, server_default="none"),
        sa.Column("hold_reason", sa.String(length=255), nullable=True),
        sa.Column("held_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("razorpay_order_id", sa.String(length=64), nullable=True),
        sa.Column("razorpay_payment_id", sa.String(length=64), nullable=True),
        sa.Column("razorpay_signature", sa.String(length=255), nullable=True),
        sa.Column("charged_currency", sa.String(length=10), nullable=False, server_default="USD"),
        sa.Column("charged_amount_minor_units", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_orders_listing_id"), "orders", ["listing_id"], unique=False)
    op.create_index(op.f("ix_orders_listing_version_id"), "orders", ["listing_version_id"], unique=False)
    op.create_index(op.f("ix_orders_buyer_id"), "orders", ["buyer_id"], unique=False)
    op.create_index(op.f("ix_orders_seller_id"), "orders", ["seller_id"], unique=False)
    op.create_index(op.f("ix_orders_status"), "orders", ["status"], unique=False)
    op.create_index(op.f("ix_orders_hold_status"), "orders", ["hold_status"], unique=False)
    op.create_index(op.f("ix_orders_razorpay_order_id"), "orders", ["razorpay_order_id"], unique=False)
    op.create_index(op.f("ix_orders_razorpay_payment_id"), "orders", ["razorpay_payment_id"], unique=False)

    # 2. entitlements
    op.create_table(
        "entitlements",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("order_id", sa.String(length=36), nullable=False),
        sa.Column("buyer_id", sa.String(length=36), nullable=False),
        sa.Column("listing_version_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_entitlements_order_id"), "entitlements", ["order_id"], unique=False)
    op.create_index(op.f("ix_entitlements_buyer_id"), "entitlements", ["buyer_id"], unique=False)
    op.create_index(op.f("ix_entitlements_listing_version_id"), "entitlements", ["listing_version_id"], unique=False)
    op.create_index(op.f("ix_entitlements_status"), "entitlements", ["status"], unique=False)

    # 3. seller_payment_profiles
    op.create_table(
        "seller_payment_profiles",
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("razorpay_account_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(op.f("ix_seller_payment_profiles_razorpay_account_id"), "seller_payment_profiles", ["razorpay_account_id"], unique=True)


def downgrade() -> None:
    op.drop_table("seller_payment_profiles")
    op.drop_table("entitlements")
    op.drop_table("orders")
