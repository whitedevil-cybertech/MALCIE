"""phase3 threat intel reputation results

Revision ID: 0005_phase3_threat_intel_reputation
Revises: 0004_phase2b_partb_yara_ioc
Create Date: 2026-09-03
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0005_threat_intel"
down_revision = "0004_yara_ioc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=True),
        sa.Column("ioc_id", sa.Integer(), nullable=True),
        sa.Column("ioc_type", sa.String(length=32), nullable=False),
        sa.Column("ioc_value", sa.Text(), nullable=False),
        sa.Column("normalized_value", sa.String(length=1024), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False, server_default="VirusTotal"),
        sa.Column("query_status", sa.String(length=32), nullable=False),
        sa.Column("reputation_score", sa.Integer(), nullable=True),
        sa.Column("malicious_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suspicious_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("harmless_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("undetected_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_engines", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detection_details", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("raw_response", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("queried_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ioc_id"], ["ioc_records.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_threat_intel_results_id"), "threat_intel_results", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_threat_intel_results_incident_id"),
        "threat_intel_results",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intel_results_artifact_id"),
        "threat_intel_results",
        ["artifact_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intel_results_ioc_id"),
        "threat_intel_results",
        ["ioc_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intel_results_ioc_type"),
        "threat_intel_results",
        ["ioc_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intel_results_normalized_value"),
        "threat_intel_results",
        ["normalized_value"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_threat_intel_results_normalized_value"), table_name="threat_intel_results"
    )
    op.drop_index(op.f("ix_threat_intel_results_ioc_type"), table_name="threat_intel_results")
    op.drop_index(op.f("ix_threat_intel_results_ioc_id"), table_name="threat_intel_results")
    op.drop_index(op.f("ix_threat_intel_results_artifact_id"), table_name="threat_intel_results")
    op.drop_index(op.f("ix_threat_intel_results_incident_id"), table_name="threat_intel_results")
    op.drop_index(op.f("ix_threat_intel_results_id"), table_name="threat_intel_results")
    op.drop_table("threat_intel_results")
