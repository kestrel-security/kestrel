# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared cron-expression validation for ConnectorInstance.schedule_cron.

Used both at write time (POST/PATCH /connector-instances, so an operator
gets an immediate 400 for a typo'd expression instead of a schedule that
silently never fires) and defensively by the worker's periodic dispatcher
(apps/worker/src/kestrel_worker/tasks/schedule.py), in case a row was ever
written some other way (direct SQL, a future bulk-import path).
"""

from __future__ import annotations

from croniter import CroniterBadCronError, CroniterBadDateError, croniter


class InvalidCronError(ValueError):
    """`schedule_cron` is not a valid 5-field cron expression."""


def validate_cron(expr: str) -> None:
    try:
        if not croniter.is_valid(expr):
            raise InvalidCronError(f"'{expr}' is not a valid cron expression")
    except (CroniterBadCronError, CroniterBadDateError) as exc:
        raise InvalidCronError(f"'{expr}' is not a valid cron expression: {exc}") from exc
