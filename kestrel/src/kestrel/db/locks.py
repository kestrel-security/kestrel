# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-org, transaction-scoped Postgres advisory locks.

Some writes rebuild an org-wide derived table wholesale (identity correlation,
the MAPS_TO graph edges) or reconcile org-wide state against a snapshot read
earlier in the transaction (policy evaluation). Two transactions doing that for
the same org at once interleave badly: the second one's DELETE waits on the
first one's row locks, then, once the first commits, inserts rows whose keys
the first one just committed, and fails on a unique constraint.

``org_advisory_xact_lock`` serialises those sections per org and per purpose.
The lock is released automatically when the surrounding transaction commits or
rolls back, so a crashed worker cannot leave it held, and it is re-entrant
within one transaction.

Ordering rule: when one transaction takes more than one of these locks, take
them in the order the purposes are listed below (correlation before
evaluation). Every caller following the same order is what keeps two syncs from
deadlocking on each other.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

#: Rebuilding ``identity_links`` and the MAPS_TO edges projected from them.
IDENTITY_CORRELATION = "identity_correlation"
#: Org-wide policy evaluation and findings reconciliation.
POLICY_EVALUATION = "policy_evaluation"


def org_advisory_xact_lock(session: Session, org_id: uuid.UUID, purpose: str) -> None:
    """Block until this transaction holds the ``(purpose, org_id)`` lock.

    Uses the two-int4 form of ``pg_advisory_xact_lock`` keyed by
    ``hashtext(purpose)`` and ``hashtext(org_id)``, so different purposes for
    one org, and one purpose across orgs, never contend. Take it *before*
    reading the state the guarded section depends on: under READ COMMITTED,
    each statement after the lock is granted sees whatever the previous holder
    committed.
    """
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:purpose), hashtext(:org_id))"),
        {"purpose": purpose, "org_id": str(org_id)},
    )
