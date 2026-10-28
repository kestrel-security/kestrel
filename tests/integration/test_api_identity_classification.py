# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- Settings -> Identity classification rules and their effect on identities."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kestrel.db.models.application import ApplicationType
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client, make_application, make_application_instance, make_connector_instance
from sqlalchemy import select


def _seed_identities(db_session, org) -> dict[str, Identity]:
    gws = make_application_instance(
        db_session,
        org,
        make_application(db_session, org, name="Google Workspace", application_type=ApplicationType.GOOGLE_WORKSPACE),
    )
    okta = make_application_instance(
        db_session, org, make_application(db_session, org, name="Okta", application_type=ApplicationType.OKTA)
    )
    run_instance = make_connector_instance(db_session, org, application_instance=gws)
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=org.id,
        connector_instance_id=run_instance.id,
        status=ConnectorRunStatus.SUCCESS,
        started_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.add(run)
    db_session.flush()

    def identity(key: str, instance, **fields) -> Identity:
        columns = {
            "identity_type": IdentityType.USER,
            "email": f"{key}@acme.example.com",
            "display_name": key,
            **fields,
        }
        row = Identity(
            id=uuid.uuid4(),
            org_id=org.id,
            application_instance_id=instance.id,
            provider_object_id=key,
            source_connector_run_id=run.id,
            raw_source={},
            **columns,
        )
        db_session.add(row)
        return row

    rows = {
        "gws-contractor": identity("gws-contractor", gws, attributes={"org_unit_path": "/Contractors/EMEA"}),
        "gws-staff": identity("gws-staff", gws, attributes={"org_unit_path": "/Engineering"}),
        "okta-contractor": identity(
            "okta-contractor",
            okta,
            worker_type="contractor",
            worker_type_source="connector",
            attributes={"connector_worker_type": "contractor"},
        ),
        "okta-bot": identity(
            "okta-bot",
            okta,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            worker_type="service",
            worker_type_source="connector",
            attributes={"connector_worker_type": "service"},
        ),
    }
    db_session.flush()
    return rows


RULES = [
    {
        "worker_type": "contractor",
        "match_kind": "org_unit_path_prefix",
        "match_value": "/Contractors",
        "application_type": "google_workspace",
        "label": "Contractors OU",
    },
    {"worker_type": "employee", "match_kind": "email_domain", "match_value": "acme.example.com"},
]


def test_saving_rules_reclassifies_existing_identities_without_a_resync(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    rows = _seed_identities(db_session, client.kestrel_org)

    put = client.put("/api/v1/settings/identity-classification", json={"rules": RULES})

    assert put.status_code == 200, put.text
    body = put.json()
    assert [r["priority"] for r in body["rules"]] == [0, 1]
    assert body["rules"][0]["match_value"] == "/Contractors"
    assert body["reclassified"] == 3  # the Okta bot stays a service account

    for row in rows.values():
        db_session.refresh(row)
    assert rows["gws-contractor"].worker_type == "contractor"
    assert rows["gws-contractor"].worker_type_source == f"rule:{body['rules'][0]['id']}"
    assert rows["gws-staff"].worker_type == "employee"
    # The domain rule outranks Okta's own "Contractor" label: operator intent wins.
    assert rows["okta-contractor"].worker_type == "employee"
    assert rows["okta-bot"].worker_type == "service"

    actions = list(db_session.scalars(select(AuditLog.action).where(AuditLog.org_id == client.kestrel_org.id)).all())
    assert "identity_classification.updated" in actions

    listed = client.get("/api/v1/identities?worker_type=contractor").json()
    assert [item["display_name"] for item in listed["items"]] == ["gws-contractor"]
    assert listed["items"][0]["worker_type_source"].startswith("rule:")


def test_removing_a_rule_falls_back_to_the_connector_value(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    rows = _seed_identities(db_session, client.kestrel_org)
    client.put("/api/v1/settings/identity-classification", json={"rules": RULES})

    put = client.put("/api/v1/settings/identity-classification", json={"rules": [RULES[0]]})

    assert put.status_code == 200, put.text
    for row in rows.values():
        db_session.refresh(row)
    assert (rows["okta-contractor"].worker_type, rows["okta-contractor"].worker_type_source) == ("contractor", "connector")
    assert (rows["gws-staff"].worker_type, rows["gws-staff"].worker_type_source) == ("unknown", None)
    assert rows["gws-contractor"].worker_type == "contractor"
    assert len(client.get("/api/v1/settings/identity-classification").json()["rules"]) == 1


def test_preview_reports_counts_without_writing(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    rows = _seed_identities(db_session, client.kestrel_org)

    preview = client.post("/api/v1/settings/identity-classification/preview", json={"rules": RULES})

    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["counts"]["contractor"] == 1
    assert body["counts"]["employee"] == 2
    assert body["counts"]["service"] == 1
    assert body["changed"] == 3
    assert body["matched_by_rule"] == [1, 2]
    db_session.refresh(rows["gws-contractor"])
    assert rows["gws-contractor"].worker_type == "unknown"


def test_a_bad_rule_is_rejected_and_leaves_the_list_untouched(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    client.put("/api/v1/settings/identity-classification", json={"rules": RULES})

    bad = client.put(
        "/api/v1/settings/identity-classification",
        json={"rules": [{"worker_type": "wizard", "match_kind": "email_domain", "match_value": "x.example"}]},
    )

    assert bad.status_code == 400
    assert "worker_type" in bad.json()["detail"]
    assert len(client.get("/api/v1/settings/identity-classification").json()["rules"]) == 2


def test_rules_are_admin_only(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    assert client.get("/api/v1/settings/identity-classification").status_code == 403
    assert client.put("/api/v1/settings/identity-classification", json={"rules": []}).status_code == 403
