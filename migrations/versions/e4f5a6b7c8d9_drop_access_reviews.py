# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Drop access review campaigns and application owners.

Access reviews never had an API or UI, so the tables, their enums, and the
application-instance owner columns that only they used are removed.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-10-05
"""

import importlib.util
from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "e4f5a6b7c8d9"
down_revision: Union[str, None] = "d3e4f5a6b7c8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ENUMS = (
    "access_review_campaign_status",
    "access_review_scope",
    "access_review_item_kind",
    "access_review_decision",
)


def upgrade() -> None:
    op.drop_table("access_review_invites")
    op.drop_table("access_review_items")
    op.drop_table("access_review_campaigns")
    for name in _ENUMS:
        op.execute(f"DROP TYPE IF EXISTS {name}")

    op.drop_constraint("fk_application_instances_owner_operator_id", "application_instances", type_="foreignkey")
    op.drop_index(op.f("ix_application_instances_owner_operator_id"), table_name="application_instances")
    op.drop_column("application_instances", "owner_email")
    op.drop_column("application_instances", "owner_operator_id")


# The revisions that built what upgrade() drops, in the order they ran.
# downgrade() replays them so the schema matches d3e4f5a6b7c8 exactly.
_SOURCE_REVISIONS = (
    "a2b3c4d5e6f7_add_access_review_campaigns",
    "g8b9c0d1e2f3_add_access_review_reviewer_ops",
    "m4n5o6p7q8r9_add_nhi_access_review_scope",
    "l3m4n5o6p7q8_add_delegated_review_invites",
)


def downgrade() -> None:
    for name in _SOURCE_REVISIONS:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.upgrade()
