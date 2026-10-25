# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Drop discovered applications, investigate saved queries, and setting baselines.

Shadow-SaaS discovery, Investigate saved queries, and configuration-drift
baselines never had an API or UI, so their tables and the
discovered-application enums are removed.

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-10-05
"""

import importlib.util
from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "f5a6b7c8d9e0"
down_revision: Union[str, None] = "e4f5a6b7c8d9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ENUMS = (
    "discovered_application_source",
    "discovered_application_status",
)


def upgrade() -> None:
    op.drop_table("discovered_applications")
    for name in _ENUMS:
        op.execute(f"DROP TYPE IF EXISTS {name}")
    op.drop_table("investigate_saved_queries")
    op.drop_table("setting_baselines")


# The revisions that built what upgrade() drops, in the order they ran.
# downgrade() replays them so the schema matches e4f5a6b7c8d9 exactly.
_SOURCE_REVISIONS = (
    "d9e0f1a2b3c4_add_investigate_saved_queries",
    "i0d1e2f3a4b5_add_discovered_applications",
    "k2l3m4n5o6p7_add_okta_discovered_source",
    "n5o6p7q8r9s0_add_setting_baselines",
    "b9c0d1e2f3a4_add_slack_connect_discovered_source",
)


def downgrade() -> None:
    for name in _SOURCE_REVISIONS:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.upgrade()
