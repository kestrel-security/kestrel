# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- demo connector instances are never synced from the API or the worker.

Their tenants come from a fixture tree only `kestrel demo up` / `demo change`
generate. A plain fixture sync reads the small bundled sample instead, and
deletion detection then removed most of the demo (found clicking Sync now).
"""

from __future__ import annotations

import kestrel_worker.celery_app  # noqa: F401  (isort: skip)  registers every task module
from kestrel.db.models.connector import SyncMode
from kestrel.db.models.operator import OperatorRole
from kestrel.demo import DEMO_CONFIG_FLAG, DEMO_INSTANCE_MARKER, DEMO_SYNC_REFUSAL
from kestrel.testing import api_client
from kestrel.testing.factories import make_application_instance, make_connector_instance

from tests.integration.test_api_factories import FakeTaskQueue
from tests.integration.test_worker_tasks import _BorrowedSession


def _instance(db_session, org, *, display_name: str, generated: bool = True, sync_mode: SyncMode = SyncMode.FIXTURES):
    app_instance = make_application_instance(db_session, org, display_name=display_name)
    config = {DEMO_CONFIG_FLAG: True} if generated else {}
    instance = make_connector_instance(
        db_session, org, application_instance=app_instance, sync_mode=sync_mode, config=config
    )
    db_session.commit()
    return instance


def test_sync_now_refuses_a_demo_instance(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    instance = _instance(db_session, client.kestrel_org, display_name=f"Acme Okta {DEMO_INSTANCE_MARKER}")

    response = client.post(f"/api/v1/connector-instances/{instance.id}/sync")

    assert response.status_code == 409
    assert response.json()["detail"] == DEMO_SYNC_REFUSAL
    assert tasks.connector_syncs == []


def test_demo_instances_are_flagged_and_others_still_sync(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    demo = _instance(db_session, client.kestrel_org, display_name=f"Acme Slack {DEMO_INSTANCE_MARKER}")
    plain = _instance(db_session, client.kestrel_org, display_name="Sandbox Slack", generated=False)

    flags = {row["id"]: row["is_demo"] for row in client.get("/api/v1/connector-instances").json()}
    assert flags[str(demo.id)] is True
    assert flags[str(plain.id)] is False
    assert client.post(f"/api/v1/connector-instances/{plain.id}/sync").status_code == 202


def test_the_worker_skips_a_demo_instance(db_session, monkeypatch):
    from kestrel_worker.tasks import sync as sync_task

    monkeypatch.setattr(sync_task, "get_sessionmaker", lambda: lambda: _BorrowedSession(db_session))
    org = api_client(db_session, OperatorRole.ADMIN).kestrel_org
    instance = _instance(db_session, org, display_name=f"Acme GitHub {DEMO_INSTANCE_MARKER}")

    result = sync_task.run_connector_sync.run(
        connector_instance_id=str(instance.id),
        connector_name="github",
        config={},
    )

    assert result == sync_task.SKIPPED_DEMO


def test_a_seeded_sample_labelled_demo_still_syncs(db_session):
    # `kestrel init --seed` labels its sample "(demo)" but syncs it from the
    # shipped fixtures, so repeating that sync is harmless.
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    sample = _instance(
        db_session, client.kestrel_org, display_name=f"Acme Corp GitHub {DEMO_INSTANCE_MARKER}", generated=False
    )

    assert client.post(f"/api/v1/connector-instances/{sample.id}/sync").status_code == 202
