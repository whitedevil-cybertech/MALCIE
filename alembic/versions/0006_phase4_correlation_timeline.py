"""phase4 correlation and timeline events

Revision ID: 0006_phase4_correlation_timeline
Revises: 0005_phase3_threat_intel_reputation
Create Date: 2026-09-04
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0006_phase4_correlation_timeline"
down_revision = "0005_phase3_threat_intel_reputation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlation_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("confidence_level", sa.String(length=32), nullable=False, server_default="LOW"),
        sa.Column("confidence_reasons", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_level", sa.String(length=32), nullable=False, server_default="LOW"),
        sa.Column("risk_reasons", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("linkages", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id"),
    )
    op.create_index(
        op.f("ix_correlation_results_id"), "correlation_results", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_correlation_results_incident_id"),
        "correlation_results",
        ["incident_id"],
        unique=True,
    )

    op.create_table(
        "timeline_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=True),
        sa.Column("ioc_id", sa.Integer(), nullable=True),
        sa.Column("event_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ioc_id"], ["ioc_records.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_timeline_events_id"), "timeline_events", ["id"], unique=False)
    op.create_index(
        op.f("ix_timeline_events_incident_id"),
        "timeline_events",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_timeline_events_timestamp"),
        "timeline_events",
        ["timestamp"],
        unique=False,
    )
    op.create_index(
        op.f("ix_timeline_events_event_type"),
        "timeline_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_timeline_events_artifact_id"),
        "timeline_events",
        ["artifact_id"],
        unique=False,
    )
    op.create_index(op.f("ix_timeline_events_ioc_id"), "timeline_events", ["ioc_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_timeline_events_ioc_id"), table_name="timeline_events")
    op.drop_index(op.f("ix_timeline_events_artifact_id"), table_name="timeline_events")
    op.drop_index(op.f("ix_timeline_events_event_type"), table_name="timeline_events")
    op.drop_index(op.f("ix_timeline_events_timestamp"), table_name="timeline_events")
    op.drop_index(op.f("ix_timeline_events_incident_id"), table_name="timeline_events")
    op.drop_index(op.f("ix_timeline_events_id"), table_name="timeline_events")
    op.drop_table("timeline_events")

    op.drop_index(op.f("ix_correlation_results_incident_id"), table_name="correlation_results")
    op.drop_index(op.f("ix_correlation_results_id"), table_name="correlation_results")
    op.drop_table("correlation_results")
