# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Remove findings and every row that references them.

``findings.id`` is referenced by seven tables; only notes and tickets cascade
at the database. The rest must be cleared first, in this order, or the delete
fails on a foreign key. Both connector deletion and policy deletion end with
the same teardown, so it lives here once.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Exception_, Finding, FindingEvidence
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.in_app_notification import OperatorInAppNotification
from kestrel.db.models.ticket import FindingTicket
from kestrel.db.models.webhook import WebhookDelivery


def purge_findings(session: Session, finding_ids: Sequence[uuid.UUID]) -> int:
    """Delete ``finding_ids`` and their dependents; returns how many findings went.

    Webhook deliveries are kept with ``finding_id`` cleared: they are an audit
    record of what was sent, not part of the finding.
    """
    ids = list(finding_ids)
    if not ids:
        return 0
    session.execute(delete(OperatorInAppNotification).where(OperatorInAppNotification.finding_id.in_(ids)))
    session.execute(update(WebhookDelivery).where(WebhookDelivery.finding_id.in_(ids)).values(finding_id=None))
    session.execute(delete(FindingEvidence).where(FindingEvidence.finding_id.in_(ids)))
    session.execute(delete(FindingNote).where(FindingNote.finding_id.in_(ids)))
    session.execute(delete(FindingWatcher).where(FindingWatcher.finding_id.in_(ids)))
    session.execute(delete(FindingTicket).where(FindingTicket.finding_id.in_(ids)))
    session.execute(delete(Exception_).where(Exception_.finding_id.in_(ids)))
    result = session.execute(delete(Finding).where(Finding.id.in_(ids)))
    return int(getattr(result, "rowcount", 0) or 0)
