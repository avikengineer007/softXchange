"""Add seller_github_connections table

Revision ID: 0003_github_connections
Revises: 0002_notifications
Create Date: 2026-09-13 18:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0003_github_connections"
down_revision: Union[str, None] = "0002_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "seller_github_connections",
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("github_username", sa.String(length=255), nullable=False),
        sa.Column("github_user_id", sa.String(length=64), nullable=False),
        sa.Column("account_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("public_repo_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(
        op.f("ix_seller_github_connections_github_user_id"),
        "seller_github_connections",
        ["github_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_seller_github_connections_github_username"),
        "seller_github_connections",
        ["github_username"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_seller_github_connections_github_username"), table_name="seller_github_connections")
    op.drop_index(op.f("ix_seller_github_connections_github_user_id"), table_name="seller_github_connections")
    op.drop_table("seller_github_connections")
