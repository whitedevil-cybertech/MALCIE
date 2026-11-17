"""add identity, ownership, encrypted graph tokens, and durable deduplication

Revision ID: 0009_identity_graph_security
Revises: 0008_ioc_classification
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_identity_graph_security"
down_revision = "0008_ioc_classification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    with op.batch_alter_table("incidents", recreate="auto") as batch:
        batch.add_column(sa.Column("owner_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_incidents_owner_id", "users", ["owner_id"], ["id"], ondelete="SET NULL"
        )
    op.create_index("ix_incidents_owner_id", "incidents", ["owner_id"])
    with op.batch_alter_table("emails", recreate="auto") as batch:
        batch.create_unique_constraint("uq_emails_graph_message_id", ["graph_message_id"])
    op.create_table(
        "graph_oauth_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("access_token_encrypted", sa.Text(), nullable=False),
        sa.Column("refresh_token_encrypted", sa.Text(), nullable=True),
        sa.Column("token_type", sa.String(32), nullable=False, server_default="Bearer"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["replaced_by_id"], ["graph_oauth_tokens.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_graph_oauth_tokens_user_id", "graph_oauth_tokens", ["user_id"])
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("notification_id", sa.String(255), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("notification_id", name="uq_webhook_deliveries_notification_id"),
    )


def downgrade() -> None:
    op.drop_table("webhook_deliveries")
    op.drop_index("ix_graph_oauth_tokens_user_id", table_name="graph_oauth_tokens")
    op.drop_table("graph_oauth_tokens")
    with op.batch_alter_table("emails", recreate="auto") as batch:
        batch.drop_constraint("uq_emails_graph_message_id", type_="unique")
    op.drop_index("ix_incidents_owner_id", table_name="incidents")
    with op.batch_alter_table("incidents", recreate="auto") as batch:
        batch.drop_constraint("fk_incidents_owner_id", type_="foreignkey")
        batch.drop_column("owner_id")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
