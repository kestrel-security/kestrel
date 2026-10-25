# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add ticket_integrations and finding_tickets.

Revision ID: j1k2l3m4n5o6
Revises: i0d1e2f3a4b5
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "j1k2l3m4n5o6"
down_revision: Union[str, None] = "i0d1e2f3a4b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ticket_integrations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("secret_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ticket_integrations_org_id"), "ticket_integrations", ["org_id"], unique=False)

    op.create_table(
        "finding_tickets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("ticket_integration_id", sa.UUID(), nullable=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("external_id", sa.String(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("created_by_operator_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["ticket_integration_id"], ["ticket_integrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_operator_id"], ["operators.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_tickets_org_id"), "finding_tickets", ["org_id"], unique=False)
    op.create_index(op.f("ix_finding_tickets_finding_id"), "finding_tickets", ["finding_id"], unique=False)
    op.create_index(
        op.f("ix_finding_tickets_ticket_integration_id"),
        "finding_tickets",
        ["ticket_integration_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_tickets_ticket_integration_id"), table_name="finding_tickets")
    op.drop_index(op.f("ix_finding_tickets_finding_id"), table_name="finding_tickets")
    op.drop_index(op.f("ix_finding_tickets_org_id"), table_name="finding_tickets")
    op.drop_table("finding_tickets")
    op.drop_index(op.f("ix_ticket_integrations_org_id"), table_name="ticket_integrations")
    op.drop_table("ticket_integrations")
