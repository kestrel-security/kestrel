# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Webhook endpoint update, delivery history, and retry rules, beyond the
create/rotate/delete basics. URLs are public IP literals so the SSRF guard
never touches DNS.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED, WebhookDelivery, WebhookDeliveryStatus
from kestrel.testing import api_client
from sqlalchemy import select

from tests.integration.test_api_factories import FakeTaskQueue, make_webhook

PUBLIC_URL = "https://93.184.216.34/kestrel-hook"


def _delivery(session, endpoint, *, status: WebhookDeliveryStatus, created_at: datetime) -> WebhookDelivery:
    row = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=endpoint.org_id,
        webhook_endpoint_id=endpoint.id,
        event_type=FINDING_OPENED,
        payload={"n": 1},
        status=status,
        attempt_count=1,
        http_status=500 if status == WebhookDeliveryStatus.FAILED else None,
        error_message="boom" if status == WebhookDeliveryStatus.FAILED else None,
        created_at=created_at,
    )
    session.add(row)
    session.flush()
    return row


def test_create_lists_and_reads_back_with_delivery_counts(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    created = client.post(
        "/api/v1/webhooks",
        json={"name": "SIEM", "url": PUBLIC_URL, "events": [FINDING_OPENED, FINDING_RESOLVED], "description": "d"},
    )

    assert created.status_code in (200, 201), created.text
    body = created.json()
    assert body["signing_secret"]
    listed = client.get("/api/v1/webhooks").json()
    rows = listed if isinstance(listed, list) else listed["items"]
    assert [r["id"] for r in rows] == [body["id"]]
    assert "signing_secret" not in rows[0]
    detail = client.get(f"/api/v1/webhooks/{body['id']}").json()
    assert sorted(detail["events"]) == sorted([FINDING_OPENED, FINDING_RESOLVED])
    assert "delivery_counts" in detail


def test_patch_updates_fields_and_is_audited(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL, description="old")
    db_session.commit()

    response = client.patch(
        f"/api/v1/webhooks/{endpoint.id}",
        json={
            "name": "Renamed",
            "url": PUBLIC_URL,
            "events": [FINDING_RESOLVED],
            "description": None,
            "is_enabled": False,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "Renamed"
    assert body["url"] == PUBLIC_URL
    assert body["events"] == [FINDING_RESOLVED]
    assert body["description"] is None
    assert body["is_enabled"] is False
    actions = db_session.scalars(select(AuditLog.action).where(AuditLog.org_id == client.kestrel_org.id)).all()
    assert "webhook.updated" in actions


def test_patch_without_description_keeps_it(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL, description="keep me")
    db_session.commit()

    response = client.patch(f"/api/v1/webhooks/{endpoint.id}", json={"name": "Only the name"})

    assert response.status_code == 200
    assert response.json()["description"] == "keep me"


@pytest.mark.parametrize(
    "patch",
    [
        {"events": ["not.an.event"]},
        {"url": "ftp://93.184.216.34/not-http"},
        {"url": "https://127.0.0.1/loopback"},
        {"url": "http://93.184.216.34/plaintext"},
        {"name": "   "},
    ],
    ids=["bad-event", "bad-scheme", "loopback", "plain-http", "blank-name"],
)
def test_patch_rejects_invalid_values(db_session, patch):
    client = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    db_session.commit()

    response = client.patch(f"/api/v1/webhooks/{endpoint.id}", json=patch)

    assert response.status_code == 400


def test_webhook_routes_are_404_for_an_unknown_or_foreign_endpoint(db_session):
    owner = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, owner.kestrel_org, url=PUBLIC_URL)
    db_session.commit()
    other = api_client(db_session, OperatorRole.ADMIN, task_queue=FakeTaskQueue())

    for webhook_id in (endpoint.id, uuid.uuid4()):
        assert other.get(f"/api/v1/webhooks/{webhook_id}").status_code == 404
        assert other.patch(f"/api/v1/webhooks/{webhook_id}", json={"name": "x"}).status_code == 404
        assert other.delete(f"/api/v1/webhooks/{webhook_id}").status_code == 404
        assert other.post(f"/api/v1/webhooks/{webhook_id}/rotate-secret").status_code == 404
        assert other.get(f"/api/v1/webhooks/{webhook_id}/deliveries").status_code == 404
        retry = other.post(f"/api/v1/webhooks/{webhook_id}/deliveries/{uuid.uuid4()}/retry")
        assert retry.status_code == 404


def test_webhooks_are_admin_only(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    assert (
        client.post("/api/v1/webhooks", json={"name": "x", "url": PUBLIC_URL, "events": [FINDING_OPENED]}).status_code == 403
    )


def test_deliveries_are_newest_first_filterable_and_limited(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    base = datetime(2026, 3, 1, tzinfo=UTC)
    oldest = _delivery(db_session, endpoint, status=WebhookDeliveryStatus.SUCCESS, created_at=base)
    middle = _delivery(db_session, endpoint, status=WebhookDeliveryStatus.FAILED, created_at=base + timedelta(hours=1))
    newest = _delivery(db_session, endpoint, status=WebhookDeliveryStatus.PENDING, created_at=base + timedelta(hours=2))
    db_session.commit()
    url = f"/api/v1/webhooks/{endpoint.id}/deliveries"

    all_rows = client.get(url).json()
    assert [r["id"] for r in all_rows] == [str(newest.id), str(middle.id), str(oldest.id)]

    failed = client.get(url, params={"status": "FAILED"}).json()
    assert [r["id"] for r in failed] == [str(middle.id)]

    limited = client.get(url, params={"limit": 2}).json()
    assert [r["id"] for r in limited] == [str(newest.id), str(middle.id)]

    counts = client.get(f"/api/v1/webhooks/{endpoint.id}").json()["delivery_counts"]
    assert counts.get("success") == 1
    assert counts.get("failed") == 1
    assert counts.get("pending") == 1


def test_deliveries_reject_an_unknown_status(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    db_session.commit()

    response = client.get(f"/api/v1/webhooks/{endpoint.id}/deliveries", params={"status": "exploded"})

    assert response.status_code == 400


def test_retry_resets_a_failed_delivery_and_keeps_its_attempt_count(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ADMIN, task_queue=tasks)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    failed = _delivery(
        db_session, endpoint, status=WebhookDeliveryStatus.FAILED, created_at=datetime(2026, 3, 1, tzinfo=UTC)
    )
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{endpoint.id}/deliveries/{failed.id}/retry")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pending"
    assert body["attempt_count"] == 1
    assert body["error_message"] is None
    assert body["http_status"] is None
    assert tasks.webhook_deliveries == [str(failed.id)]


def test_a_successful_delivery_cannot_be_retried(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ADMIN, task_queue=tasks)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    done = _delivery(db_session, endpoint, status=WebhookDeliveryStatus.SUCCESS, created_at=datetime(2026, 3, 1, tzinfo=UTC))
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{endpoint.id}/deliveries/{done.id}/retry")

    assert response.status_code == 400
    assert tasks.webhook_deliveries == []


def test_a_delivery_on_a_disabled_endpoint_cannot_be_retried(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ADMIN, task_queue=tasks)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    failed = _delivery(
        db_session, endpoint, status=WebhookDeliveryStatus.FAILED, created_at=datetime(2026, 3, 1, tzinfo=UTC)
    )
    endpoint.is_enabled = False
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{endpoint.id}/deliveries/{failed.id}/retry")

    assert response.status_code == 400
    assert "disabled" in response.json()["detail"]


def test_a_delivery_cannot_be_retried_through_another_endpoint(db_session):
    client = api_client(db_session, OperatorRole.ADMIN, task_queue=FakeTaskQueue())
    first, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    second, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    failed = _delivery(db_session, first, status=WebhookDeliveryStatus.FAILED, created_at=datetime(2026, 3, 1, tzinfo=UTC))
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{second.id}/deliveries/{failed.id}/retry")

    assert response.status_code == 404


def test_delete_drops_delivery_history(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    endpoint, _ = make_webhook(db_session, client.kestrel_org, url=PUBLIC_URL)
    _delivery(db_session, endpoint, status=WebhookDeliveryStatus.FAILED, created_at=datetime(2026, 3, 1, tzinfo=UTC))
    db_session.commit()
    endpoint_id = endpoint.id

    assert client.delete(f"/api/v1/webhooks/{endpoint_id}").status_code == 204

    remaining = db_session.scalars(select(WebhookDelivery).where(WebhookDelivery.webhook_endpoint_id == endpoint_id)).all()
    assert remaining == []
