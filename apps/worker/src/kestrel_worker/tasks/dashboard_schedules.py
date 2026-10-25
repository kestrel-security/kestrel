# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery task: dispatch due dashboard email schedules."""

from __future__ import annotations

from kestrel.dashboard.schedules import dispatch_due_schedules
from kestrel.db.session import get_sessionmaker

from kestrel_worker.celery_app import app


@app.task(name="kestrel.dashboard.dispatch_schedules")
def dispatch_dashboard_schedules() -> int:
    session = get_sessionmaker()()
    try:
        return dispatch_due_schedules(session)
    finally:
        session.close()
