# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Every foreign key into the rows a connector delete removes is handled.

``kestrel.connectors.delete`` removes a connector instance, its runs, and (when
nothing else is bound to it) its application instance. A table that references
any of those and is not cleared first makes the delete fail with a foreign-key
violation -- which is how cursors and graph snapshots broke it before. This
test reads the SQLAlchemy metadata, so adding such a table without teaching the
delete about it fails here rather than at an operator's first delete.
"""

from __future__ import annotations

import kestrel.db.models  # noqa: F401 -- registers every table on Base.metadata
from kestrel.connectors.delete import CLEARED_REFERENCES, DELETED_TABLES
from kestrel.db.base import Base


def _references_in_metadata() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for table in Base.metadata.tables.values():
        for fk in table.foreign_keys:
            if fk.column.table.name in DELETED_TABLES:
                found.add((table.name, fk.parent.name))
    return found


def test_every_reference_to_a_deleted_table_is_cleared_by_the_delete():
    in_schema = _references_in_metadata()
    missing = sorted(in_schema - CLEARED_REFERENCES)
    assert not missing, (
        f"Foreign keys into {sorted(DELETED_TABLES)} that connectors/delete.py does not clear: {missing}. "
        "Delete or null these rows in delete_connector_instance, then add them to CLEARED_REFERENCES."
    )


def test_the_cleared_list_has_no_stale_entries():
    stale = sorted(CLEARED_REFERENCES - _references_in_metadata())
    assert not stale, f"CLEARED_REFERENCES names columns that no longer reference a deleted table: {stale}"
