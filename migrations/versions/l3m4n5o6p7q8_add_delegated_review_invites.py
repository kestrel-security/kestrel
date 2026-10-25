# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add delegated access-review invites + instance owners.

Revision ID: l3m4n5o6p7q8
Revises: k2l3m4n5o6p7
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "l3m4n5o6p7q8"
down_revision: Union[str, None] = "k2l3m4n5o6p7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "application_instances",
        sa.Column("owner_operator_id", sa.UUID(), nullable=True),
    )
    op.add_column(
        "application_instances",
        sa.Column("owner_email", sa.String(length=320), nullable=True),
    )
    op.create_index(
        op.f("ix_application_instances_owner_operator_id"),
        "application_instances",
        ["owner_operator_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_application_instances_owner_operator_id",
        "application_instances",
        "operators",
        ["owner_operator_id"],
        ["id"],
    )

    op.add_column(
        "access_review_items",
        sa.Column("assigned_reviewer_email", sa.String(length=320), nullable=True),
    )
    op.create_index(
        op.f("ix_access_review_items_assigned_reviewer_email"),
        "access_review_items",
        ["assigned_reviewer_email"],
        unique=False,
    )

    op.create_table(
        "access_review_invites",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("reviewer_email", sa.String(length=320), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_operator_id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["access_review_campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_access_review_invites_token_hash"),
    )
    op.create_index(op.f("ix_access_review_invites_org_id"), "access_review_invites", ["org_id"], unique=False)
    op.create_index(
        op.f("ix_access_review_invites_campaign_id"),
        "access_review_invites",
        ["campaign_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_access_review_invites_reviewer_email"),
        "access_review_invites",
        ["reviewer_email"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_access_review_invites_reviewer_email"), table_name="access_review_invites")
    op.drop_index(op.f("ix_access_review_invites_campaign_id"), table_name="access_review_invites")
    op.drop_index(op.f("ix_access_review_invites_org_id"), table_name="access_review_invites")
    op.drop_table("access_review_invites")

    op.drop_index(op.f("ix_access_review_items_assigned_reviewer_email"), table_name="access_review_items")
    op.drop_column("access_review_items", "assigned_reviewer_email")

    op.drop_constraint("fk_application_instances_owner_operator_id", "application_instances", type_="foreignkey")
    op.drop_index(op.f("ix_application_instances_owner_operator_id"), table_name="application_instances")
    op.drop_column("application_instances", "owner_email")
    op.drop_column("application_instances", "owner_operator_id")
