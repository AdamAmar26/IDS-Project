"""Expand feature windows (6 new columns), add alert verdict, incident notes, kill chain

Revision ID: 002
Revises: 001
Create Date: 2026-04-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("feature_windows") as batch_op:
        batch_op.add_column(sa.Column("privileged_process_count", sa.Integer(), server_default="0"))
        batch_op.add_column(sa.Column("parent_child_anomaly_score", sa.Float(), server_default="0"))
        batch_op.add_column(sa.Column("dns_query_count", sa.Integer(), server_default="0"))
        batch_op.add_column(sa.Column("unique_parent_processes", sa.Integer(), server_default="0"))
        batch_op.add_column(sa.Column("memory_usage_spike", sa.Float(), server_default="0"))
        batch_op.add_column(sa.Column("sensitive_file_access_count", sa.Integer(), server_default="0"))

    with op.batch_alter_table("alerts") as batch_op:
        batch_op.add_column(sa.Column("verdict", sa.String(), nullable=True))

    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(sa.Column("kill_chain_phase", sa.String(), nullable=True))

    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("author", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_incident_notes_incident_id")
    op.drop_table("incident_notes")

    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_column("kill_chain_phase")

    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_column("verdict")

    with op.batch_alter_table("feature_windows") as batch_op:
        batch_op.drop_column("sensitive_file_access_count")
        batch_op.drop_column("memory_usage_spike")
        batch_op.drop_column("unique_parent_processes")
        batch_op.drop_column("dns_query_count")
        batch_op.drop_column("parent_child_anomaly_score")
        batch_op.drop_column("privileged_process_count")
