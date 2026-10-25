# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Reconcile the migrated schema with the ORM models.

Revision ID: l1a2b3c4d5e6
Revises: k0f1a2b3c4d5
Create Date: 2026-10-10

`alembic check` (tests/system/test_migration_replay.py) found two places where
the models and the chain disagreed:

* ``graph_snapshots.org_id`` is declared ``index=True`` by ``TenantMixin`` but
  the table's migration only created the composite instance index.
* ``identity_links.computed_at`` is non-nullable in the model (every row is
  written by the correlation rebuild, which always sets it) but the column was
  created nullable.

Everything else that check flagged was the models under-declaring what the
database already had (partial indexes, the settings tables' ON DELETE CASCADE)
and is fixed on the model side with no schema change.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "l1a2b3c4d5e6"
down_revision: Union[str, None] = "k0f1a2b3c4d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(op.f("ix_graph_snapshots_org_id"), "graph_snapshots", ["org_id"], unique=False)
    op.execute("UPDATE identity_links SET computed_at = now() WHERE computed_at IS NULL")
    op.alter_column("identity_links", "computed_at", nullable=False)


def downgrade() -> None:
    op.alter_column("identity_links", "computed_at", nullable=True)
    op.drop_index(op.f("ix_graph_snapshots_org_id"), table_name="graph_snapshots")
