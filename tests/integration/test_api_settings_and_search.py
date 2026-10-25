# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Behavior for the small single-purpose routers -- notification
preferences, org AI settings, search, and the two public (no-auth)
endpoints -- that don't warrant their own file. Role gating is covered by
test_api_auth_matrix.py.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def test_notification_preferences_round_trip(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    defaults = client.get("/api/v1/notification-preferences")
    assert defaults.status_code == 200
    assert defaults.json()["email_enabled"] is True  # default per kestrel.notifications.preferences

    patched = client.patch(
        "/api/v1/notification-preferences",
        json={"email_enabled": False, "min_severity": "high", "muted_events": ["finding.opened"]},
    )
    assert patched.status_code == 200
    body = patched.json()
    assert body["email_enabled"] is False
    assert body["min_severity"] == "high"
    assert body["muted_events"] == ["finding.opened"]

    refetched = client.get("/api/v1/notification-preferences")
    assert refetched.json()["email_enabled"] is False


def test_ai_settings_round_trip_and_never_echoes_the_key(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    empty = client.get("/api/v1/settings/ai")
    assert empty.status_code == 200
    assert empty.json()["configured"] is False

    put = client.put(
        "/api/v1/settings/ai",
        json={"provider": "openai", "model": "gpt-4o-mini", "api_key": "sk-super-secret-value"},
    )
    assert put.status_code == 200
    body = put.json()
    assert body["configured"] is True
    assert body["api_key_configured"] is True
    assert "sk-super-secret-value" not in put.text

    cleared = client.delete("/api/v1/settings/ai")
    assert cleared.status_code == 200
    assert cleared.json()["cleared"] is True

    after = client.get("/api/v1/settings/ai")
    assert after.json()["configured"] is False


def test_search_groups_results_by_entity_type(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/search", params={"q": "test"})

    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_policy_validate_requires_authentication(db_session):
    """Validation compiles the submitted source, so it is not open to anonymous callers."""
    client = api_client(db_session)

    response = client.post(
        "/api/v1/policies/validate",
        json={"source_text": "not valid policy source"},
        headers={"Authorization": ""},
    )

    assert response.status_code == 401


def test_policy_validate_reports_errors_to_an_analyst(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/policies/validate", json={"source_text": "not valid policy source"})

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["errors"]


def test_policy_validate_rejects_oversized_source(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/policies/validate", json={"source_text": "x" * (64 * 1024 + 1)})

    assert response.status_code == 422


def test_change_classes_requires_authentication(db_session):
    """Every /api/v1 route takes a bearer token, even one that only returns
    enum vocabulary: a single anonymous route breaks the invariant the auth
    matrix test relies on and would need its own rate-limit treatment."""
    client = api_client(db_session)

    assert client.get("/api/v1/changes/classes", headers={"Authorization": ""}).status_code == 401

    response = client.get("/api/v1/changes/classes")

    assert response.status_code == 200
    body = response.json()
    assert "classes" in body
    assert "significance" in body


def test_search_finds_people_and_collapses_their_accounts(db_session):
    """ "find Grace" is the most common search; four accounts is one hit."""
    from kestrel.db.models.application import ApplicationType
    from kestrel.identities.correlate import rebuild_identity_links
    from kestrel.testing import make_application, make_application_instance

    from tests.integration.test_api_factories import make_identity

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    okta_app = make_application(db_session, org, application_type=ApplicationType.OKTA)
    okta_instance = make_application_instance(db_session, org, application=okta_app)
    github_app = make_application(db_session, org, application_type=ApplicationType.GITHUB)
    github_instance = make_application_instance(db_session, org, application=github_app)
    make_identity(db_session, org, application_instance=okta_instance, email="grace@acme.test", display_name="Grace Hopper")
    make_identity(
        db_session, org, application_instance=github_instance, email="grace@acme.test", display_name="Grace Hopper"
    )
    rebuild_identity_links(db_session, org_id=org.id)
    db_session.commit()

    response = client.get("/api/v1/search", params={"q": "Grace"})

    assert response.status_code == 200
    groups = {group["type"]: group["items"] for group in response.json()["groups"]}
    assert "identity" in groups
    assert len(groups["identity"]) == 1
    hit = groups["identity"][0]
    assert hit["label"] == "Grace Hopper"
    assert hit["href"].startswith("/identities/")
    assert "2 applications" in (hit["subtitle"] or "")


def test_search_omits_a_tombstoned_person(db_session):
    from datetime import UTC, datetime

    from tests.integration.test_api_factories import make_identity

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    identity = make_identity(db_session, org, email="departed.person@acme.test", display_name="Departed Person")
    identity.deleted_at = datetime.now(UTC)
    db_session.commit()

    response = client.get("/api/v1/search", params={"q": "Departed"})

    groups = {group["type"]: group["items"] for group in response.json()["groups"]}
    assert groups.get("identity") == []
