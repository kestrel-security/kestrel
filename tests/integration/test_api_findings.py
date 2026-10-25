# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Findings investigation behavior beyond the auth/tenant/pagination
matrices: mute/unmute, verify (dry-run remediation check), handoff export,
bulk patch, watch, notes, exceptions, and ticket dry-run creation.
"""

from __future__ import annotations

import httpx
import pytest
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client, make_operator, make_organization
from kestrel.ticketing.create import TicketCreateError, create_ticket_for_finding

from tests.integration.test_api_factories import (
    FakeTaskQueue,
    make_finding,
    make_findings_batch,
    make_ticket_integration,
    make_webhook,
)


def test_mute_requires_days_or_muted_until(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/findings/{finding.id}/mute", json={})

    assert response.status_code == 422


def test_mute_rejects_both_days_and_muted_until(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.post(
        f"/api/v1/findings/{finding.id}/mute",
        json={"days": 7, "muted_until": "2099-01-01T00:00:00Z"},
    )

    assert response.status_code == 422


def test_mute_for_days_then_unmute_reopens(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    muted = client.post(f"/api/v1/findings/{finding.id}/mute", json={"days": 5, "reason": "known issue"})
    assert muted.status_code == 200
    assert muted.json()["status"] == "muted"

    unmuted = client.post(f"/api/v1/findings/{finding.id}/unmute")
    assert unmuted.status_code == 200
    assert unmuted.json()["status"] == "open"


def test_patch_cannot_set_status_to_muted_directly(db_session):
    """Mute requires POST .../mute (which enforces an expiry) -- PATCH
    status=muted is rejected so a mute can never be created without one."""
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.patch(f"/api/v1/findings/{finding.id}", json={"status": "muted"})

    assert response.status_code == 422


def test_verify_reports_still_matches_for_an_unresolved_condition(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)  # built from an always-non-compliant policy
    db_session.commit()

    response = client.post(f"/api/v1/findings/{finding.id}/verify", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "still_matches"
    assert body["still_matches"] is True


def _finding_on_instance(db_session, org, *, config: dict | None = None):
    from kestrel.testing.factories import make_application_instance, make_connector_instance

    from tests.integration.test_api_factories import make_identity

    app_instance = make_application_instance(db_session, org)
    instance = make_connector_instance(db_session, org, application_instance=app_instance, config=config or {})
    identity = make_identity(db_session, org, connector_instance=instance)
    finding = make_finding(db_session, org, identity=identity)
    db_session.commit()
    return finding, instance


def test_verify_with_trigger_sync_enqueues_a_sync(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    finding, instance = _finding_on_instance(db_session, client.kestrel_org)

    response = client.post(f"/api/v1/findings/{finding.id}/verify", json={"trigger_sync": True})

    assert response.status_code == 200, response.text
    assert [s["connector_instance_id"] for s in tasks.connector_syncs] == [str(instance.id)]


def test_verify_with_trigger_sync_refuses_while_a_sync_is_running(db_session):
    """Verify used to enqueue straight to the broker, skipping the guards on "Sync now"."""
    import uuid
    from datetime import UTC, datetime

    from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    finding, instance = _finding_on_instance(db_session, client.kestrel_org)
    running = ConnectorRun(
        id=uuid.uuid4(),
        org_id=instance.org_id,
        connector_instance_id=instance.id,
        status=ConnectorRunStatus.RUNNING,
        started_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.add(running)
    db_session.commit()

    response = client.post(f"/api/v1/findings/{finding.id}/verify", json={"trigger_sync": True})

    assert response.status_code == 409
    assert response.json()["detail"]["run_id"] == str(running.id)
    assert tasks.connector_syncs == []


def test_verify_with_trigger_sync_refuses_a_demo_instance(db_session):
    from kestrel.demo import DEMO_CONFIG_FLAG, DEMO_SYNC_REFUSAL

    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    finding, _instance = _finding_on_instance(db_session, client.kestrel_org, config={DEMO_CONFIG_FLAG: True})

    response = client.post(f"/api/v1/findings/{finding.id}/verify", json={"trigger_sync": True})

    assert response.status_code == 409
    assert response.json()["detail"] == DEMO_SYNC_REFUSAL
    assert tasks.connector_syncs == []


def test_handoff_markdown_and_json_both_succeed(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    markdown = client.get(f"/api/v1/findings/{finding.id}/handoff")
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")

    as_json = client.get(f"/api/v1/findings/{finding.id}/handoff", params={"format": "json"})
    assert as_json.status_code == 200
    body = as_json.json()
    assert body["finding"]["id"] == str(finding.id)


def test_handoff_rejects_an_unknown_format(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.get(f"/api/v1/findings/{finding.id}/handoff", params={"format": "yaml"})

    assert response.status_code == 422


def test_bulk_patch_updates_all_and_reports_unknown_ids(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    findings = make_findings_batch(db_session, org, 3)
    db_session.commit()
    unknown_id = "00000000-0000-0000-0000-000000000000"

    response = client.post(
        "/api/v1/findings/bulk",
        json={
            "finding_ids": [str(f.id) for f in findings] + [unknown_id],
            "status": "resolved",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["updated_count"] == 3
    assert body["not_found"] == [unknown_id]
    assert all(row["status"] == "resolved" for row in body["updated"])


def test_watch_then_unwatch_round_trips(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    assert client.get(f"/api/v1/findings/{finding.id}/watch").json()["watching"] is False

    watched = client.post(f"/api/v1/findings/{finding.id}/watch")
    assert watched.status_code == 200
    assert watched.json()["watching"] is True
    assert client.get(f"/api/v1/findings/{finding.id}/watch").json()["watching"] is True

    unwatched = client.delete(f"/api/v1/findings/{finding.id}/watch")
    assert unwatched.status_code == 200
    assert unwatched.json()["watching"] is False


def test_notes_are_appended_and_both_listed(db_session):
    """Both notes land in `items`; a strict newest-first assertion isn't
    reliable here because both requests share one transaction timestamp
    (`FindingNote.created_at` is `server_default=func.now()`) -- the
    (created_at, id) tiebreak ordering itself is exactly what
    test_api_pagination.py's duplicate-sort-key contract already covers."""
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    first = client.post(f"/api/v1/findings/{finding.id}/notes", json={"body": "first note"})
    second = client.post(f"/api/v1/findings/{finding.id}/notes", json={"body": "second note"})
    assert first.status_code == 201
    assert second.status_code == 201

    listed = client.get(f"/api/v1/findings/{finding.id}/notes")
    assert listed.status_code == 200
    bodies = {n["body"] for n in listed.json()["items"]}
    assert bodies == {"first note", "second note"}


def test_exception_requires_a_non_empty_reason(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/findings/{finding.id}/exceptions", json={"reason": ""})

    assert response.status_code == 422


def test_exception_is_created_with_the_authenticated_actor(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/findings/{finding.id}/exceptions", json={"reason": "accepted risk for Q3"})

    assert response.status_code == 201
    body = response.json()
    assert body["reason"] == "accepted risk for Q3"
    assert body["created_by"]["email"] == client.kestrel_operator.email


def test_dry_run_ticket_create_writes_nothing_and_calls_no_network(db_session):
    """dry_run=true short-circuits the GitHub Issues provider before any
    httpx call is made (see connectors: providers honor dry_run)."""
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    integration = make_ticket_integration(db_session, org, provider="github_issues")
    db_session.commit()

    response = client.post(
        f"/api/v1/findings/{finding.id}/tickets",
        json={"integration_id": str(integration.id), "dry_run": True},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["dry_run"] is True
    assert body["ticket"] is None

    listed = client.get(f"/api/v1/findings/{finding.id}/tickets")
    assert listed.json()["items"] == []


def test_an_unreachable_tracker_is_a_ticket_create_error_not_a_crash(db_session):
    org = make_organization(db_session)
    actor = make_operator(db_session, org)
    finding = make_finding(db_session, org)
    token = "test-token-unreachable-0123456789"
    integration = make_ticket_integration(db_session, org, api_token=token)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"connection refused (token {token})", request=request)

    with pytest.raises(TicketCreateError, match="ticket provider request failed: ConnectError") as raised:
        create_ticket_for_finding(
            db_session,
            finding=finding,
            integration=integration,
            actor_operator_id=actor.id,
            http_client=httpx.Client(transport=httpx.MockTransport(refuse)),
        )
    assert token not in str(raised.value)


def test_get_finding_404_for_unknown_id(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/findings/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404


def test_identity_subject_links_to_identity_page_and_explore(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    db_session.commit()

    response = client.get(f"/api/v1/findings/{finding.id}")

    assert response.status_code == 200
    subject = response.json()["subject"]
    assert subject["detail_path"] == f"/identities/{finding.subject_id}"
    assert subject["graph_focus_path"] == f"/explore?focus={finding.subject_id}&focus_type=identity&direction=out"


def test_unmute_enqueues_a_finding_opened_webhook_delivery(db_session):
    """Reopening via unmute schedules FINDING_OPENED webhooks -- asserted
    through the injectable task queue, never a real broker."""
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    org = client.kestrel_org
    finding = make_finding(db_session, org)
    from kestrel.db.models.webhook import FINDING_OPENED

    make_webhook(db_session, org, events=[FINDING_OPENED])
    db_session.commit()

    muted = client.post(f"/api/v1/findings/{finding.id}/mute", json={"days": 1})
    assert muted.status_code == 200

    response = client.post(f"/api/v1/findings/{finding.id}/unmute")

    assert response.status_code == 200
    assert len(tasks.webhook_deliveries) == 1
