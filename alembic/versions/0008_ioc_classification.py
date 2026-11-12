"""classify IOC provenance and interpretation

Revision ID: 0008_ioc_classification
Revises: 0007_phase5_sysmon_telemetry
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_ioc_classification"
down_revision = "0007_sysmon_telemetry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ioc_records",
        sa.Column("classification", sa.String(length=32), nullable=False, server_default="extracted"),
    )


def downgrade() -> None:
    op.drop_column("ioc_records", "classification")
