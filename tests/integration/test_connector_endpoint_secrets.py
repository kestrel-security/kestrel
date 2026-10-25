# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""A connector's stored credentials never follow it to a new host.

Regression for the "point org_url at your own server, then Test connection"
credential theft: PATCH /connector-instances/{id} must clear the stored
secrets when a URL / host config field changes (unless new ones arrive in the
same request), and record that in the audit log. The same rule covers the
Jira ticket integration and the org LLM settings.

URLs are public IP literals so the SSRF guard never touches DNS.
"""

from __future__ import annotations

from kestrel.db.models.audit import AuditLog
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client
from sqlalchemy import select

OLD_URL = "https://93.184.216.34"
NEW_URL = "https://93.184.216.35"


def _okta_instance_with_token(client, *, org_url: str = OLD_URL) -> str:
    created = client.post(
        "/api/v1/connector-instances",
        json={
            "connector_name": "okta",
            "display_name": "Okta",
            "external_tenant_ref": f"okta-{client.kestrel_org.id.hex[:8]}",
            "auth_method": "pat",
            "sync_mode": "fixtures",
            "config": {"org_url": org_url},
        },
    )
    assert created.status_code == 201, created.text
    instance_id = created.json()["id"]
    put = client.put(
        f"/api/v1/connector-instances/{instance_id}/secrets",
        json={"secrets": {"api_token": "ssws-original-token-value"}},
    )
    assert put.status_code == 200, put.text
    assert put.json()["configured_fields"] == ["api_token"]
    return instance_id


def _configured(client, instance_id: str) -> list[str]:
    return client.get(f"/api/v1/connector-instances/{instance_id}/secrets").json()["configured_fields"]


def test_changing_the_org_url_clears_stored_secrets_and_is_audited(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _okta_instance_with_token(client)

    response = client.patch(f"/api/v1/connector-instances/{instance_id}", json={"config": {"org_url": NEW_URL}})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["endpoint_fields_changed"] == ["org_url"]
    assert body["secrets_cleared"] == ["api_token"]
    assert body["secrets_reentry_required"] is True
    assert _configured(client, instance_id) == []

    event = db_session.scalars(
        select(AuditLog).where(
            AuditLog.org_id == client.kestrel_org.id,
            AuditLog.action == "connector_instance.updated",
        )
    ).one()
    assert event.context["endpoint_fields_changed"] == ["org_url"]
    assert event.context["secrets_cleared"] == ["api_token"]


def test_secrets_sent_with_the_url_change_are_kept(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _okta_instance_with_token(client)

    response = client.patch(
        f"/api/v1/connector-instances/{instance_id}",
        json={"config": {"org_url": NEW_URL}, "secrets": {"api_token": "ssws-reentered-token"}},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["secrets_cleared"] == []
    assert body["secrets_reentry_required"] is False
    assert _configured(client, instance_id) == ["api_token"]


def test_resaving_the_same_url_keeps_secrets(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _okta_instance_with_token(client)

    response = client.patch(
        f"/api/v1/connector-instances/{instance_id}",
        json={"config": {"org_url": OLD_URL + "/"}, "display_name": "Okta prod"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["secrets_cleared"] == []
    assert _configured(client, instance_id) == ["api_token"]


def test_live_mode_rejects_plain_http_urls(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _okta_instance_with_token(client)

    response = client.patch(
        f"/api/v1/connector-instances/{instance_id}",
        json={"config": {"org_url": "http://93.184.216.34"}, "sync_mode": "live"},
    )

    assert response.status_code == 400
    assert "https" in response.json()["detail"]
    assert _configured(client, instance_id) == ["api_token"]


def test_switching_to_live_revalidates_a_fixture_mode_http_url(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _okta_instance_with_token(client, org_url="http://93.184.216.34")

    response = client.patch(f"/api/v1/connector-instances/{instance_id}", json={"sync_mode": "live"})

    assert response.status_code == 400
    assert "https" in response.json()["detail"]


def _jira_integration(client) -> str:
    created = client.post(
        "/api/v1/ticket-integrations",
        json={
            "name": "Jira",
            "provider": "jira_cloud",
            "api_token": "jira-original-token",
            "config": {"base_url": OLD_URL, "project_key": "SEC", "email": "bot@example.com"},
        },
    )
    assert created.status_code in (200, 201), created.text
    return created.json()["id"]


def test_jira_base_url_change_requires_the_token_again(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    integration_id = _jira_integration(client)
    new_config = {"base_url": NEW_URL, "project_key": "SEC", "email": "bot@example.com"}

    refused = client.patch(f"/api/v1/ticket-integrations/{integration_id}", json={"config": new_config})
    assert refused.status_code == 400
    assert "api_token" in refused.json()["detail"]

    accepted = client.patch(
        f"/api/v1/ticket-integrations/{integration_id}",
        json={"config": new_config, "api_token": "jira-reentered-token"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["config"]["base_url"] == NEW_URL


def test_jira_non_endpoint_change_keeps_the_token(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    integration_id = _jira_integration(client)

    response = client.patch(
        f"/api/v1/ticket-integrations/{integration_id}",
        json={"config": {"base_url": OLD_URL, "project_key": "OPS", "email": "bot@example.com"}},
    )

    assert response.status_code == 200, response.text


def test_llm_endpoint_change_requires_the_key_again(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    first = client.put(
        "/api/v1/settings/ai",
        json={"provider": "openai", "base_url": OLD_URL + "/v1", "api_key": "sk-original-key"},
    )
    assert first.status_code == 200, first.text

    moved = client.put("/api/v1/settings/ai", json={"provider": "openai", "base_url": NEW_URL + "/v1"})
    assert moved.status_code == 400
    assert "api_key" in moved.json()["detail"]

    switched = client.put("/api/v1/settings/ai", json={"provider": "anthropic"})
    assert switched.status_code == 400

    same = client.put("/api/v1/settings/ai", json={"provider": "openai", "base_url": OLD_URL + "/v1", "model": "m"})
    assert same.status_code == 200, same.text

    rekeyed = client.put(
        "/api/v1/settings/ai",
        json={"provider": "openai", "base_url": NEW_URL + "/v1", "api_key": "sk-reentered-key"},
    )
    assert rekeyed.status_code == 200, rekeyed.text
