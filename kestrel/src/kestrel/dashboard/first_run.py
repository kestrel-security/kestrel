# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator dismissal of the first-run checklist.

``posture_overview()["first_run"]`` is computed from org state and hides
itself once every step is done. Until then an operator can dismiss it; the
choice is theirs alone and lives under
``Operator.ui_preferences["first_run_dismissed_at"]``, next to the dashboard
layout, so it needs no migration. Restoring pops the key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.operator import Operator

FIRST_RUN_DISMISSED_KEY = "first_run_dismissed_at"


def first_run_dismissed(operator: Operator) -> bool:
    prefs = operator.ui_preferences or {}
    return bool(prefs.get(FIRST_RUN_DISMISSED_KEY))


def _state(operator: Operator) -> dict[str, Any]:
    prefs = operator.ui_preferences or {}
    dismissed_at = prefs.get(FIRST_RUN_DISMISSED_KEY)
    return {"dismissed": bool(dismissed_at), "dismissed_at": dismissed_at or None}


def dismiss_first_run(db: Session, operator: Operator) -> dict[str, Any]:
    prefs = dict(operator.ui_preferences or {})
    prefs[FIRST_RUN_DISMISSED_KEY] = datetime.now(UTC).isoformat()
    operator.ui_preferences = prefs
    db.add(operator)
    db.flush()
    return _state(operator)


def restore_first_run(db: Session, operator: Operator) -> dict[str, Any]:
    prefs = dict(operator.ui_preferences or {})
    prefs.pop(FIRST_RUN_DISMISSED_KEY, None)
    operator.ui_preferences = prefs
    db.add(operator)
    db.flush()
    return _state(operator)
