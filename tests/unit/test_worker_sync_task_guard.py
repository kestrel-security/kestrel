# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The sync task's concurrency guard and hardening options, without a broker
or a database: the lock decides before any session is opened."""

from __future__ import annotations

import httpx
import pytest

# The Celery app registers every task module on import; importing a task
# module before it re-enters that registration half-initialized.
import kestrel_worker.celery_app  # noqa: F401  (isort: skip)
from kestrel_worker.tasks import sync as sync_task
from kestrel_worker.tasks.sync import SKIPPED_ALREADY_RUNNING, run_connector_sync


class _HeldLock:
    def acquire(self, connector_instance_id):
        return None

    def release(self, connector_instance_id, token):
        raise AssertionError("nothing to release when the lock was never taken")


def test_a_held_lock_skips_the_sync_before_touching_the_database(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sync_task, "get_sync_lock", lambda: _HeldLock())
    monkeypatch.setattr(sync_task, "load_connector", lambda name: object())

    def _no_session():
        raise AssertionError("a skipped sync must not open a session")

    monkeypatch.setattr(sync_task, "get_sessionmaker", _no_session)

    result = run_connector_sync.run(
        connector_instance_id="00000000-0000-0000-0000-000000000001", connector_name="github", config={}
    )

    assert result == SKIPPED_ALREADY_RUNNING


def test_task_options_bound_runtime_and_retry_only_transport_errors():
    assert run_connector_sync.acks_late is True
    assert run_connector_sync.soft_time_limit is not None
    assert run_connector_sync.time_limit is not None
    assert run_connector_sync.time_limit > run_connector_sync.soft_time_limit
    assert httpx.TransportError in run_connector_sync.autoretry_for
    # An auth or permission failure is not transient; it must not be in the set.
    assert httpx.HTTPStatusError not in run_connector_sync.autoretry_for
    assert ValueError not in run_connector_sync.autoretry_for
