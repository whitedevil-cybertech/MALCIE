"""add correlation versioning and investigation reports table

Revision ID: 0010_correlation_reports
Revises: 0009_identity_graph_security
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_correlation_reports"
down_revision = "0009_identity_graph_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Update correlation_results table
    with op.batch_alter_table("correlation_results", recreate="auto") as batch:
        batch.add_column(
            sa.Column(
                "algorithm_version",
                sa.String(32),
                nullable=False,
                server_default="2.1.0",
            )
        )
        batch.add_column(
            sa.Column(
                "scoring_version",
                sa.String(32),
                nullable=False,
                server_default="2.1.0",
            )
        )
        batch.add_column(
            sa.Column(
                "missing_evidence",
                sa.JSON(),
                nullable=False,
                server_default="[]",
            )
        )
        batch.add_column(
            sa.Column(
                "score_breakdown",
                sa.JSON(),
                nullable=False,
                server_default="{}",
            )
        )

    # 2. Create investigation_reports table
    op.create_table(
        "investigation_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("report_id", sa.String(64), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("author_id", sa.Integer(), nullable=True),
        sa.Column("author_email", sa.String(320), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("disposition", sa.String(64), nullable=False, server_default="under_investigation"),
        sa.Column("correlation_version", sa.String(32), nullable=False, server_default="2.1.0"),
        sa.Column("scoring_version", sa.String(32), nullable=False, server_default="2.1.0"),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("evidence_snapshot", sa.JSON(), nullable=False),
        sa.Column("report_data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("report_id", name="uq_investigation_reports_report_id"),
        sa.UniqueConstraint(
            "incident_id", "version", name="uq_investigation_reports_incident_version"
        ),
    )
    op.create_index("ix_investigation_reports_report_id", "investigation_reports", ["report_id"])
    op.create_index("ix_investigation_reports_incident_id", "investigation_reports", ["incident_id"])
    op.create_index("ix_investigation_reports_author_id", "investigation_reports", ["author_id"])


def downgrade() -> None:
    op.drop_index("ix_investigation_reports_author_id", table_name="investigation_reports")
    op.drop_index("ix_investigation_reports_incident_id", table_name="investigation_reports")
    op.drop_index("ix_investigation_reports_report_id", table_name="investigation_reports")
    op.drop_table("investigation_reports")

    with op.batch_alter_table("correlation_results", recreate="auto") as batch:
        batch.drop_column("score_breakdown")
        batch.drop_column("missing_evidence")
        batch.drop_column("scoring_version")
        batch.drop_column("algorithm_version")
