# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The demo walkthrough path, end to end over the API.

Every step a presenter takes, in order, against a small estate this test owns:
connectors → identities → one person across applications → the cross-app
finding → its evidence and subject → changes. A regression anywhere in that
chain is a broken demo, and the chain crosses enough modules that no single
unit test covers it.

Deliberately not a browser test: what can break here is the data and the API
shape, and those are what this asserts. Rendering is covered by the web
typecheck and build.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from kestrel.db.models.application import ApplicationType
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.findings.pipeline import evaluate_all_enabled_policies
from kestrel.identities.correlate import rebuild_identity_links
from kestrel.testing import api_client, make_application, make_application_instance, make_connector_instance

# The shipped cross-app policy, read from the pack so the test exercises the
# real source rather than a copy that can drift from it.
_POLICY_PATH = Path("packs/cross-app/policies/cross_app_departed_still_has_access.py")
_DEPARTED_POLICY = _POLICY_PATH.read_text()


def _contract_value(key: str, default: str = "") -> str:
    """Read a module-level constant out of the policy source, the way
    `install_pack` does, so the demo asserts the shipped text."""
    for line in _DEPARTED_POLICY.splitlines():
        if line.startswith(f"{key} = "):
            return line.split("=", 1)[1].strip().strip('"')
    return default


_REMEDIATION = _contract_value("REMEDIATION")


def _tenant(db_session, org, app_type: ApplicationType):
    application = make_application(db_session, org, application_type=app_type)
    app_instance = make_application_instance(db_session, org, application=application)
    connector_instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=org.id,
        connector_instance_id=connector_instance.id,
        status=ConnectorRunStatus.SUCCESS,
        started_at=datetime.now(UTC) - timedelta(minutes=5),
        finished_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.SCHEDULE,
        object_counts={"identity": 1},
    )
    db_session.add(run)
    db_session.flush()
    return app_instance, run


def _identity(db_session, org, app_instance, run, *, email: str, name: str, disabled: bool) -> Identity:
    row = Identity(
        id=uuid.uuid4(),
        org_id=org.id,
        application_instance_id=app_instance.id,
        provider_object_id=f"user-{uuid.uuid4().hex[:8]}",
        identity_type=IdentityType.USER,
        email=email,
        display_name=name,
        is_disabled=disabled,
        source_connector_run_id=run.id,
        raw_source={},
    )
    db_session.add(row)
    db_session.flush()
    return row


def _install_policy(db_session, org) -> PolicyVersion:
    policy = Policy(
        id=uuid.uuid4(),
        org_id=org.id,
        slug="cross-app-departed-still-has-access",
        title=_contract_value("TITLE", "Departed still has access"),
        source=PolicySource.PACK,
    )
    db_session.add(policy)
    db_session.flush()
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version=1,
        source_text=_DEPARTED_POLICY,
        severity=Severity.CRITICAL,
        remediation=_REMEDIATION,
        compliance_mappings={},
        is_enabled=True,
    )
    db_session.add(version)
    db_session.flush()
    policy.current_version_id = version.id
    db_session.flush()
    return version


def test_the_demo_path_holds_end_to_end(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org

    # An offboarded person: disabled in the identity provider, still live in a
    # collaboration tool. This is the finding the demo is built around.
    okta_instance, okta_run = _tenant(db_session, org, ApplicationType.OKTA)
    slack_instance, slack_run = _tenant(db_session, org, ApplicationType.SLACK)
    departed_okta = _identity(
        db_session, org, okta_instance, okta_run, email="departed@acme.test", name="Dana Departed", disabled=True
    )
    departed_slack = _identity(
        db_session, org, slack_instance, slack_run, email="departed@acme.test", name="Dana Departed", disabled=False
    )
    _identity(db_session, org, okta_instance, okta_run, email="present@acme.test", name="Pat Present", disabled=False)
    rebuild_identity_links(db_session, org_id=org.id)
    _install_policy(db_session, org)
    evaluate_all_enabled_policies(db_session, org_id=org.id)
    db_session.commit()

    # 1. Integrations: both tenants are connected and their last run succeeded.
    instances = client.get("/api/v1/connector-instances").json()
    assert len(instances) >= 2
    assert all(row["last_run_status"] == "success" for row in instances)

    # 2. Identities: the person is one row, not two.
    listed = client.get("/api/v1/identities", params={"collapse": "true", "search": "Dana"}).json()["items"]
    assert len(listed) == 1
    assert sorted(listed[0]["application_types"]) == ["okta", "slack"]
    assert listed[0]["account_count"] == 2

    # 3. Identity detail: both accounts, with the disabled one visible.
    overview = client.get(f"/api/v1/identities/{departed_slack.id}/overview").json()
    accounts = {a["application_type"]: a for a in overview["cluster"]["accounts"]}
    assert accounts["okta"]["is_disabled"] is True
    assert accounts["slack"]["is_disabled"] is False

    # 4. Findings: the cross-app policy fired, and against the surviving account.
    findings = client.get("/api/v1/findings", params={"status": "open"}).json()["items"]
    departed = [f for f in findings if f["policy_slug"] == "cross-app-departed-still-has-access"]
    assert len(departed) == 1, "exactly one finding: the account that outlived the offboarding"
    assert departed[0]["subject_id"] == str(departed_slack.id)
    assert departed[0]["severity"] == "critical"

    # 5. Finding detail: evidence names both sides, and the subject links to
    #    the person's other accounts.
    detail = client.get(f"/api/v1/findings/{departed[0]['id']}").json()
    evidence = {row["label"]: row["value"] for row in detail["evidence"]}
    assert evidence["cluster.idp_status"] == "disabled"
    assert detail["subject"]["cluster"]["member_count"] == 2
    assert detail["subject"]["identity_path"] == f"/identities/{departed_slack.id}"
    assert detail["policy"]["remediation"]

    # 6. Search: typing the name finds the person, collapsed.
    groups = {g["type"]: g["items"] for g in client.get("/api/v1/search", params={"q": "Dana"}).json()["groups"]}
    assert len(groups["identity"]) == 1
    assert groups["identity"][0]["href"].startswith("/identities/")

    # The identity-provider account itself is not the finding: offboarding it
    # was the correct action.
    assert str(departed_okta.id) not in {f["subject_id"] for f in departed}


def test_the_demo_path_survives_a_re_sync(db_session):
    """Re-running evaluation must not double the finding or move its subject."""
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    okta_instance, okta_run = _tenant(db_session, org, ApplicationType.OKTA)
    slack_instance, slack_run = _tenant(db_session, org, ApplicationType.SLACK)
    _identity(db_session, org, okta_instance, okta_run, email="d@acme.test", name="Dee Departed", disabled=True)
    survivor = _identity(
        db_session, org, slack_instance, slack_run, email="d@acme.test", name="Dee Departed", disabled=False
    )
    rebuild_identity_links(db_session, org_id=org.id)
    _install_policy(db_session, org)
    evaluate_all_enabled_policies(db_session, org_id=org.id)
    evaluate_all_enabled_policies(db_session, org_id=org.id)
    db_session.commit()

    findings = client.get("/api/v1/findings", params={"status": "open"}).json()["items"]
    departed = [f for f in findings if f["policy_slug"] == "cross-app-departed-still-has-access"]
    assert len(departed) == 1
    assert departed[0]["subject_id"] == str(survivor.id)


def test_offboarding_the_last_account_resolves_the_finding(db_session):
    """Finishing the job is what closes it -- the demo's remediation beat."""
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    okta_instance, okta_run = _tenant(db_session, org, ApplicationType.OKTA)
    slack_instance, slack_run = _tenant(db_session, org, ApplicationType.SLACK)
    _identity(db_session, org, okta_instance, okta_run, email="z@acme.test", name="Zed Departed", disabled=True)
    survivor = _identity(
        db_session, org, slack_instance, slack_run, email="z@acme.test", name="Zed Departed", disabled=False
    )
    rebuild_identity_links(db_session, org_id=org.id)
    _install_policy(db_session, org)
    evaluate_all_enabled_policies(db_session, org_id=org.id)
    db_session.commit()
    assert client.get("/api/v1/findings", params={"status": "open"}).json()["items"]

    # The operator disables the surviving account in Slack; the next sync sees it.
    survivor.is_disabled = True
    db_session.flush()
    evaluate_all_enabled_policies(db_session, org_id=org.id)
    db_session.commit()

    open_findings = client.get("/api/v1/findings", params={"status": "open"}).json()["items"]
    assert [f for f in open_findings if f["policy_slug"] == "cross-app-departed-still-has-access"] == []
