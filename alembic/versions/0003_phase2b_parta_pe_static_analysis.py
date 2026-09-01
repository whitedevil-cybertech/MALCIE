"""phase2b part a pe static analysis

Revision ID: 0003_phase2b_parta_pe_static_analysis
Revises: 0002_phase2a_email_intake
Create Date: 2026-09-01
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0003_phase2b_parta_pe_static_analysis"
down_revision = "0002_phase2a_email_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_analyses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("is_pe", sa.Boolean(), nullable=False),
        sa.Column("file_type", sa.String(length=64), nullable=True),
        sa.Column("pe_headers", sa.JSON(), nullable=False),
        sa.Column("sections", sa.JSON(), nullable=False),
        sa.Column("imports", sa.JSON(), nullable=False),
        sa.Column("extracted_strings", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id"),
    )
    op.create_index(op.f("ix_artifact_analyses_artifact_id"), "artifact_analyses", ["artifact_id"], unique=True)
    op.create_index(op.f("ix_artifact_analyses_id"), "artifact_analyses", ["id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_artifact_analyses_id"), table_name="artifact_analyses")
    op.drop_index(op.f("ix_artifact_analyses_artifact_id"), table_name="artifact_analyses")
    op.drop_table("artifact_analyses")
