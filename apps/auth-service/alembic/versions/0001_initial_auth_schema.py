"""Initial auth service schema

Revision ID: 0001_auth_schema
Revises: 
Create Date: 2026-09-12 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_auth_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # 2. refresh_tokens
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_refresh_tokens_token_hash"), "refresh_tokens", ["token_hash"], unique=True)
    op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"], unique=False)

    # 3. seller_profiles
    op.create_table(
        "seller_profiles",
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("kyc_status", sa.String(length=32), nullable=False, server_default="not_started"),
        sa.Column("payout_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("payout_account_id", sa.String(length=255), nullable=True),
        sa.Column("kyc_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(op.f("ix_seller_profiles_kyc_status"), "seller_profiles", ["kyc_status"], unique=False)

    # 4. verification_tokens
    op.create_table(
        "verification_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_verification_tokens_token_hash"), "verification_tokens", ["token_hash"], unique=True)
    op.create_index(op.f("ix_verification_tokens_user_id"), "verification_tokens", ["user_id"], unique=False)
    op.create_index(op.f("ix_verification_tokens_purpose"), "verification_tokens", ["purpose"], unique=False)

    # 5. admin_provision_audit_logs
    op.create_table(
        "admin_provision_audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("failure_reason", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_admin_provision_audit_logs_user_id"), "admin_provision_audit_logs", ["user_id"], unique=False)
    op.create_index(op.f("ix_admin_provision_audit_logs_timestamp"), "admin_provision_audit_logs", ["timestamp"], unique=False)

    # 6. admin_provisioning_state
    op.create_table(
        "admin_provisioning_state",
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("used_by", sa.String(length=36), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("code_hash"),
    )


def downgrade() -> None:
    op.drop_table("admin_provisioning_state")
    op.drop_table("admin_provision_audit_logs")
    op.drop_table("verification_tokens")
    op.drop_table("seller_profiles")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
