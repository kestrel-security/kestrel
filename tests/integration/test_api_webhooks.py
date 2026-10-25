# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Webhook endpoint behavior beyond the auth/tenant matrices: the signing
secret is returned once on create and never again, rotate-secret issues a
new one, and delivery retry goes through the injectable task queue rather
than a real broker.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

from tests.integration.test_api_factories import FakeTaskQueue, make_webhook


def test_create_returns_the_signing_secret_once(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/webhooks",
        json={"name": "Test webhook", "url": "https://93.184.216.34/hook", "events": ["finding.opened"]},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["signing_secret"].startswith("whsec_")

    # GET never re-exposes it.
    follow_up = client.get(f"/api/v1/webhooks/{body['id']}")
    assert follow_up.status_code == 200
    assert "signing_secret" not in follow_up.json()


def test_create_rejects_an_unsupported_event_type(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/webhooks",
        json={"name": "Bad events", "url": "https://93.184.216.34/hook", "events": ["not.a.real.event"]},
    )

    assert response.status_code == 400


def test_create_rejects_a_plain_http_url(db_session, monkeypatch):
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/webhooks",
        json={"name": "Plaintext", "url": "http://93.184.216.34/hook", "events": ["finding.opened"]},
    )

    assert response.status_code == 400
    assert "https" in response.text


def test_rotate_secret_returns_a_different_secret(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    endpoint, original_secret = make_webhook(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{endpoint.id}/rotate-secret")

    assert response.status_code == 200
    body = response.json()
    assert body["signing_secret"].startswith("whsec_")
    assert body["signing_secret"] != original_secret


def test_delete_removes_the_endpoint(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    endpoint, _secret = make_webhook(db_session, org)
    db_session.commit()

    response = client.delete(f"/api/v1/webhooks/{endpoint.id}")
    assert response.status_code == 204

    follow_up = client.get(f"/api/v1/webhooks/{endpoint.id}")
    assert follow_up.status_code == 404


def test_retry_delivery_enqueues_through_the_task_queue(db_session):
    import uuid

    from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus

    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ADMIN, task_queue=tasks)
    org = client.kestrel_org
    endpoint, _secret = make_webhook(db_session, org)
    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        event_type="finding.opened",
        payload={"hello": "world"},
        status=WebhookDeliveryStatus.FAILED,
        attempt_count=1,
    )
    db_session.add(delivery)
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{endpoint.id}/deliveries/{delivery.id}/retry")

    assert response.status_code == 200
    assert tasks.webhook_deliveries == [str(delivery.id)]


def test_retry_unknown_delivery_is_404(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    endpoint, _secret = make_webhook(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/webhooks/{endpoint.id}/deliveries/00000000-0000-0000-0000-000000000000/retry")

    assert response.status_code == 404
