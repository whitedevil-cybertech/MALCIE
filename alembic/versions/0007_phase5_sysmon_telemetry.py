"""phase5 sysmon endpoint telemetry

Revision ID: 0007_phase5_sysmon_telemetry
Revises: 0006_phase4_correlation_timeline
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_phase5_sysmon_telemetry"
down_revision = "0006_phase4_correlation_timeline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoint_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("endpoint_id", sa.String(length=512), nullable=True),
        sa.Column("user_name", sa.String(length=512), nullable=True),
        sa.Column("process_guid", sa.String(length=255), nullable=True),
        sa.Column("process_id", sa.String(length=64), nullable=True),
        sa.Column("parent_process_guid", sa.String(length=255), nullable=True),
        sa.Column("parent_process_id", sa.String(length=64), nullable=True),
        sa.Column("image", sa.String(length=2048), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("hashes", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("destination_ip", sa.String(length=128), nullable=True),
        sa.Column("destination_hostname", sa.String(length=512), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column("target_filename", sa.String(length=2048), nullable=True),
        sa.Column("registry_key", sa.String(length=2048), nullable=True),
        sa.Column("registry_value_name", sa.String(length=512), nullable=True),
        sa.Column("registry_value_data", sa.Text(), nullable=True),
        sa.Column("raw_evidence", sa.Text(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint", name="uq_endpoint_events_fingerprint"),
    )
    for column in (
        "id",
        "incident_id",
        "event_id",
        "timestamp",
        "hostname",
        "endpoint_id",
        "destination_ip",
        "destination_hostname",
        "fingerprint",
    ):
        op.create_index(
            f"ix_endpoint_events_{column}", "endpoint_events", [column], unique=False
        )


def downgrade() -> None:
    for column in (
        "fingerprint",
        "destination_hostname",
        "destination_ip",
        "endpoint_id",
        "hostname",
        "timestamp",
        "event_id",
        "incident_id",
        "id",
    ):
        op.drop_index(f"ix_endpoint_events_{column}", table_name="endpoint_events")
    op.drop_table("endpoint_events")
