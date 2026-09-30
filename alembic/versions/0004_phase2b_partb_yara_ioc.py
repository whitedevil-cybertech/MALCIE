"""phase2b part b yara and ioc records

Revision ID: 0004_phase2b_partb_yara_ioc
Revises: 0003_phase2b_parta_pe_static_analysis
Create Date: 2026-09-02
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0004_phase2b_partb_yara_ioc"
down_revision = "0003_phase2b_parta_pe_static_analysis"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "artifact_analyses",
        sa.Column("yara_matches", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "artifact_analyses",
        sa.Column("md5", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "artifact_analyses",
        sa.Column("sha1", sa.String(length=40), nullable=True),
    )

    op.create_table(
        "ioc_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=True),
        sa.Column("ioc_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized_value", sa.String(length=1024), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("context", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ioc_records_id"), "ioc_records", ["id"], unique=False)
    op.create_index(
        op.f("ix_ioc_records_incident_id"),
        "ioc_records",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ioc_records_artifact_id"),
        "ioc_records",
        ["artifact_id"],
        unique=False,
    )
    op.create_index(op.f("ix_ioc_records_ioc_type"), "ioc_records", ["ioc_type"], unique=False)

    op.create_index(
        op.f("ix_ioc_records_normalized_value"),
        "ioc_records",
        ["normalized_value"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_ioc_records_normalized_value"), table_name="ioc_records")
    op.drop_index(op.f("ix_ioc_records_ioc_type"), table_name="ioc_records")
    op.drop_index(op.f("ix_ioc_records_artifact_id"), table_name="ioc_records")
    op.drop_index(op.f("ix_ioc_records_incident_id"), table_name="ioc_records")
    op.drop_index(op.f("ix_ioc_records_id"), table_name="ioc_records")
    op.drop_table("ioc_records")

    op.drop_column("artifact_analyses", "sha1")
    op.drop_column("artifact_analyses", "md5")
    op.drop_column("artifact_analyses", "yara_matches")
