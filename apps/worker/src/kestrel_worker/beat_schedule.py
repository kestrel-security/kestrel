# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Celery beat schedule.

Beat's schedule map is static and can't itself vary per ConnectorInstance
row, so rather than one entry per instance, there's a single dispatcher
entry that runs every minute and does the per-instance schedule_cron
evaluation itself (kestrel_worker.tasks.schedule.dispatch_scheduled_syncs).
Requires running `celery -A kestrel_worker.celery_app beat` alongside the
worker -- see docs/operations/scheduled-syncs.md.
"""

from kestrel_worker.celery_app import app

app.conf.beat_schedule = {
    "dispatch-scheduled-connector-syncs": {
        "task": "kestrel.schedule.dispatch_scheduled_syncs",
        "schedule": 60.0,
    },
    "dispatch-dashboard-schedules": {
        "task": "kestrel.dashboard.dispatch_schedules",
        "schedule": 60.0,
    },
    # Audit logs are append-only and cursored, so they can be polled far more
    # often than a full inventory sync without re-walking the directory
    # . Deliberately a separate entry from the schedule_cron
    # dispatcher: an operator picks their inventory cadence, and this one is
    # not theirs to tune per instance.
    "dispatch-event-syncs": {
        "task": "kestrel.schedule.dispatch_event_syncs",
        "schedule": 300.0,
    },
    # The dashboard trend widget reads one row per org per UTC day. Hourly
    # rather than daily on purpose: the capture is an idempotent upsert on
    # (org_id, snapshot_date), so an hourly cadence means a worker restart or
    # a few hours of downtime cannot silently cost a day's data point, and it
    # keeps today's figure current instead of frozen at whenever it first ran.
    "capture-posture-trend": {
        "task": "kestrel.posture.capture_daily_snapshot",
        "schedule": 3600.0,
    },
    # Weekly per operator, but checked hourly: whether a digest is due is
    # decided per operator from when their last one went out (recorded in the
    # audit log), so a restart or an operator who just opted in is picked up
    # within the hour rather than waiting for a fixed weekly slot.
    "send-watched-finding-digests": {
        "task": "kestrel.notifications.send_watch_digests",
        "schedule": 3600.0,
    },
    # Mutes and dated exceptions end on their own. Every 5 minutes so an
    # expiry is acted on about as promptly as the audit-log poll notices a new
    # event; a pass with nothing expired is two indexed queries per org.
    "reopen-expired-finding-deferrals": {
        "task": "kestrel.findings.reopen_expired_deferrals",
        "schedule": 300.0,
    },
}
