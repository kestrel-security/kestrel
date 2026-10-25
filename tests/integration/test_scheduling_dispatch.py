# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the beat dispatcher's ``_is_due`` logic
(``kestrel_worker.tasks.schedule``).

``_is_due(cron_expr, now)`` already takes its clock as an explicit
parameter, so these tests inject fixed ``datetime`` values directly --
no ``time.sleep``, no wall-clock comparison.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kestrel.scheduling.cron import InvalidCronError, validate_cron
from kestrel_worker.tasks.schedule import _is_due


def test_is_due_true_when_fire_time_falls_inside_the_dispatch_window():
    # Every-minute cron: always has a fire time in the last minute.
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert _is_due("* * * * *", now) is True


def test_is_due_true_at_the_exact_scheduled_minute():
    # Daily at 09:00; "now" lands exactly on the scheduled minute.
    now = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    assert _is_due("0 9 * * *", now) is True


def test_is_due_false_when_next_fire_is_outside_the_window():
    # Daily at 09:00; "now" is 9:05 -- next fire is tomorrow, well outside the window.
    now = datetime(2026, 1, 1, 9, 5, tzinfo=UTC)
    assert _is_due("0 9 * * *", now) is False


def test_is_due_false_just_before_the_window_opens():
    # Daily at 09:00; "now" is one second before the window would catch it.
    now = datetime(2026, 1, 1, 8, 58, 59, tzinfo=UTC)
    assert _is_due("0 9 * * *", now) is False


def test_is_due_raises_for_a_malformed_cron_expression():
    from croniter import CroniterBadCronError

    with pytest.raises(CroniterBadCronError):
        _is_due("not a cron expression", datetime(2026, 1, 1, tzinfo=UTC))


def test_validate_cron_accepts_standard_five_field_expressions():
    validate_cron("*/15 * * * *")  # must not raise


def test_validate_cron_rejects_garbage():
    with pytest.raises(InvalidCronError):
        validate_cron("not a cron expression")
