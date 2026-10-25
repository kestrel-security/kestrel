# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Every beat entry must name a task that is actually registered.

Celery resolves `beat_schedule[...]["task"]` by string at fire time. A typo, or
a task module that never gets imported in `celery_app`, fails silently: beat
publishes a message nobody consumes, and the only symptom is a feature that
quietly never runs -- which is exactly how the posture trend table ended up
with no production writer.
"""

from __future__ import annotations

# The Celery app registers every task module on import; importing a task module
# first would re-enter that registration half-initialized.
import kestrel_worker.celery_app  # noqa: F401  (isort: skip)
import pytest
from kestrel_worker.celery_app import app

BEAT_ENTRIES = sorted(app.conf.beat_schedule.items())


@pytest.mark.parametrize(("name", "entry"), BEAT_ENTRIES, ids=[n for n, _ in BEAT_ENTRIES])
def test_every_beat_entry_names_a_registered_task(name: str, entry: dict) -> None:
    assert entry["task"] in app.tasks, (
        f"beat entry {name!r} fires {entry['task']!r}, which is not registered. "
        "Add its module to the explicit imports in kestrel_worker.celery_app."
    )


@pytest.mark.parametrize(("name", "entry"), BEAT_ENTRIES, ids=[n for n, _ in BEAT_ENTRIES])
def test_every_beat_entry_has_a_positive_interval(name: str, entry: dict) -> None:
    assert float(entry["schedule"]) > 0


def test_the_posture_trend_capture_is_scheduled() -> None:
    """It has no other trigger: no API route, no CLI command, no sync hook."""
    tasks = {entry["task"] for entry in app.conf.beat_schedule.values()}
    assert "kestrel.posture.capture_daily_snapshot" in tasks


def test_expired_mutes_and_exceptions_are_reopened_on_a_schedule() -> None:
    """Nothing else moves an expired mute or exception back to open."""
    tasks = {entry["task"] for entry in app.conf.beat_schedule.values()}
    assert "kestrel.findings.reopen_expired_deferrals" in tasks


def test_the_watched_findings_digest_is_scheduled() -> None:
    """Beat is the only thing that sends it; the API route only previews."""
    tasks = {entry["task"] for entry in app.conf.beat_schedule.values()}
    assert "kestrel.notifications.send_watch_digests" in tasks
