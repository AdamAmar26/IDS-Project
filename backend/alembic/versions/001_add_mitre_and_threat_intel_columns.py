"""Add MITRE ATT&CK and threat intel columns to incidents

Revision ID: 001
Revises: None
Create Date: 2026-04-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(sa.Column("mitre_tactics", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("mitre_techniques", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("threat_intel_hits", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_column("threat_intel_hits")
        batch_op.drop_column("mitre_techniques")
        batch_op.drop_column("mitre_tactics")
