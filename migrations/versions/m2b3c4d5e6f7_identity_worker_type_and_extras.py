# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Identity worker type, profile fields, lifecycle timestamps, and attributes.

Revision ID: m2b3c4d5e6f7
Revises: l1a2b3c4d5e6
Create Date: 2026-10-28

Cross-application policies need to know what kind of person an account belongs
to (``worker_type``), when the provider disabled it or will expire it, and the
profile fields connectors already read but had nowhere to store. ``attributes``
keeps every other provider extra that used to survive only in ``raw_source``.

All additive. ``worker_type`` is backfilled from ``identity_type`` where that
is conclusive: bots are ``service`` and outside collaborators are ``guest``;
everyone else starts as ``unknown`` until the next sync classifies them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "m2b3c4d5e6f7"
down_revision: str | None = "l1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "identities",
        sa.Column("worker_type", sa.String(length=32), nullable=False, server_default="unknown"),
    )
    op.add_column("identities", sa.Column("worker_type_source", sa.String(), nullable=True))
    op.add_column("identities", sa.Column("department", sa.String(), nullable=True))
    op.add_column("identities", sa.Column("title", sa.String(), nullable=True))
    op.add_column("identities", sa.Column("manager_email", sa.String(), nullable=True))
    op.add_column("identities", sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("identities", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "identities",
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_index(
        "ix_identities_org_worker_type",
        "identities",
        ["org_id", "worker_type"],
        unique=False,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.execute("UPDATE identities SET worker_type = 'service' WHERE identity_type = 'service_account'")
    op.execute("UPDATE identities SET worker_type = 'guest' WHERE identity_type = 'external_identity'")


def downgrade() -> None:
    op.drop_index("ix_identities_org_worker_type", table_name="identities", postgresql_where=sa.text("deleted_at IS NULL"))
    op.drop_column("identities", "attributes")
    op.drop_column("identities", "expires_at")
    op.drop_column("identities", "disabled_at")
    op.drop_column("identities", "manager_email")
    op.drop_column("identities", "title")
    op.drop_column("identities", "department")
    op.drop_column("identities", "worker_type_source")
    op.drop_column("identities", "worker_type")
