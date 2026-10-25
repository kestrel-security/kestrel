# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- policy row loaders (`policies.dataload`).

The loaders had no test coverage at all, adds the three unlocks
without which most per-resource posture is unreachable by policy:

* `RESOURCE_TYPE = "resource"` had no loader, so no policy could iterate a
  repository, channel, drive, or site no matter what a connector collected.
* `_event_dict` dropped `ActivityEvent.attributes`, so an event policy could
  only see the coarse curated action, never the branch, scope, or target the
  normalizer had preserved.
* Settings were tenant-wide only, so a branch protection rule had nowhere to
  attach except the org, with the repo name buried in the setting key.

Rows are built through `upsert_provenance_objects` rather than by inserting
model rows directly, because the subject-ref resolution being tested happens
there.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.policies.dataload import (
    LOADERS,
    RESOURCE_TYPE_TO_FROM_TYPE,
    load_event_rows,
    load_resource_rows,
    load_rows,
    load_setting_rows,
)
from kestrel.sync.upsert import UpsertContext, upsert_provenance_objects
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy.orm import Session


def _repo(provider_id: str, *, name: str, visibility: str = "private") -> NormalizedObject:
    return NormalizedObject(
        kind="resource",
        provider_id=provider_id,
        attributes={
            "resource_type": "repository",
            "name": name,
            "visibility": visibility,
            "is_sensitive": False,
        },
        raw_source={},
    )


def _setting(
    provider_id: str,
    *,
    key: str,
    value: object,
    subject_ref: str | None = None,
    category: str = "security",
) -> NormalizedObject:
    attributes: dict[str, object] = {
        "key": key,
        "category": category,
        "label": key.replace("_", " ").title(),
        "value": value,
        "value_type": "boolean" if isinstance(value, bool) else "string",
    }
    if subject_ref is not None:
        attributes["subject_type"] = "resource"
        attributes["subject_ref"] = subject_ref
    return NormalizedObject(kind="setting", provider_id=provider_id, attributes=attributes, raw_source={})


def _audit_event(provider_id: str, *, attributes: dict[str, object] | None = None) -> NormalizedObject:
    payload: dict[str, object] = {
        "action": "branch_protection.disable",
        "action_category": "config",
        "actor_email": "dana@acme.test",
        "occurred_at": datetime.now(UTC).isoformat(),
        "summary": "branch protection removed",
    }
    if attributes is not None:
        payload["attributes"] = attributes
    return NormalizedObject(kind="event", provider_id=provider_id, attributes=payload, raw_source={})


class _World:
    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.connector_instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()

    def upsert(self, objects: list[NormalizedObject]) -> None:
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=self.connector_instance.id,
            status=ConnectorRunStatus.RUNNING,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        ctx = UpsertContext(
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            connector_run_id=run.id,
            connector_instance_id=self.connector_instance.id,
        )
        upsert_provenance_objects(self.session, objects, ctx)
        self.session.flush()


def test_resource_rows_are_loadable_at_all(db_session: Session):
    world = _World(db_session)
    world.upsert([_repo("r1", name="web-app"), _repo("r2", name="secrets-vault")])

    rows = load_resource_rows(db_session, world.org.id)

    assert {row["resource"]["name"] for row in rows} == {"web-app", "secrets-vault"}
    assert all(row["_subject_type"] == "resource" for row in rows)
    assert all(row["application"] for row in rows)


def test_resource_type_resource_resolves_to_the_new_loader(db_session: Session):
    # The end an author touches: RESOURCE_TYPE = "resource" in a policy file.
    world = _World(db_session)
    world.upsert([_repo("r1", name="web-app")])

    from_type = RESOURCE_TYPE_TO_FROM_TYPE["resource"]
    assert from_type in LOADERS
    assert len(load_rows(db_session, world.org.id, from_type)) == 1


def test_a_subject_scoped_setting_attaches_to_its_resource(db_session: Session):
    world = _World(db_session)
    world.upsert(
        [
            _repo("r1", name="web-app"),
            _repo("r2", name="docs"),
            _setting("s1", key="branch_protection_enabled", value=False, subject_ref="r1"),
        ]
    )

    rows = {row["resource"]["name"]: row for row in load_resource_rows(db_session, world.org.id)}

    web_app = rows["web-app"]
    assert web_app["settings_by_key"]["branch_protection_enabled"]["value"] is False
    # The setting governs one repo; the other must not inherit it.
    assert rows["docs"]["settings"] == []
    assert rows["docs"]["settings_by_key"] == {}


def test_subject_resolution_does_not_depend_on_the_order_the_normalizer_emits(db_session: Session):
    # A connector author should not have to know that resources must be
    # normalized before the settings that reference them.
    world = _World(db_session)
    world.upsert(
        [
            _setting("s1", key="branch_protection_enabled", value=False, subject_ref="r1"),
            _repo("r1", name="web-app"),
        ]
    )

    rows = load_resource_rows(db_session, world.org.id)
    assert rows[0]["settings_by_key"]["branch_protection_enabled"]["value"] is False


def test_a_setting_whose_subject_is_absent_stays_tenant_wide(db_session: Session):
    # Partial coverage must not drop the setting entirely.
    world = _World(db_session)
    world.upsert([_setting("s1", key="branch_protection_enabled", value=False, subject_ref="missing")])

    assert load_resource_rows(db_session, world.org.id) == []
    tenant_rows = load_setting_rows(db_session, world.org.id)
    assert len(tenant_rows) == 1
    assert tenant_rows[0]["setting"]["key"] == "branch_protection_enabled"


def test_tenant_wide_settings_are_unchanged_by_subject_scoping(db_session: Session):
    world = _World(db_session)
    world.upsert(
        [
            _repo("r1", name="web-app"),
            _setting("s1", key="two_factor_required", value=False),
            _setting("s2", key="branch_protection_enabled", value=False, subject_ref="r1"),
        ]
    )

    # load_setting_rows is the tenant_setting policy surface; it lists both,
    # since a subject-scoped setting is still a setting.
    keys = {row["setting"]["key"] for row in load_setting_rows(db_session, world.org.id)}
    assert keys == {"two_factor_required", "branch_protection_enabled"}


def test_event_attributes_reach_event_policies(db_session: Session):
    world = _World(db_session)
    world.upsert([_audit_event("e1", attributes={"repo": "web-app", "branch": "main"})])

    rows = load_event_rows(db_session, world.org.id)
    assert len(rows) == 1
    assert rows[0]["event"]["attributes"] == {"repo": "web-app", "branch": "main"}


def test_event_attributes_default_to_an_empty_dict_not_none(db_session: Session):
    # So a policy can write event["attributes"].get(...) without a guard.
    world = _World(db_session)
    world.upsert([_audit_event("e1")])

    rows = load_event_rows(db_session, world.org.id)
    assert rows[0]["event"]["attributes"] == {}


def test_a_connector_can_attach_settings_to_the_resources_they_govern(db_session: Session):
    """Resource loader and subject-scoped settings end to end, through a real connector's fixtures.

    The GitHub connector emits per-repository posture as subject-scoped
    settings. This asserts the whole chain works -- normalizer declares
    `subject_ref`, upsert resolves it against the run's id map, and
    `load_resource_rows` hands the policy author a repository row with its own
    settings on it -- without asserting on any particular fixture's contents.
    """
    from kestrel.connectors.sdk.registry import discover_connectors, load_fixture_transport_builder
    from kestrel.connectors.sdk.runner import run_collection

    registration = discover_connectors()["github"]
    connector = registration.connector_class()
    collection = run_collection(
        connector,
        config=dict(registration.connector_class.manifest.example_config),
        transport_override=load_fixture_transport_builder("github")(),
    )

    world = _World(db_session)
    world.upsert(collection.normalized_objects)

    rows = load_resource_rows(db_session, world.org.id)
    assert rows, "the GitHub fixtures should produce repositories"

    scoped = [row for row in rows if row["settings"]]
    assert scoped, "at least one repository should carry its own settings"
    for row in scoped:
        # Every attached setting belongs to this repository, not the tenant.
        assert set(row["settings_by_key"]) == {s["key"] for s in row["settings"]}


def test_identity_rows_carry_the_cross_app_cluster(db_session):
    """The cross-app context every cluster policy reads: the person's other
    accounts, whether their IdP account is still active, and where they are
    privileged."""
    import uuid as _uuid

    from kestrel.db.models.application import ApplicationType
    from kestrel.db.models.identity import Identity, IdentityType
    from kestrel.identities.correlate import rebuild_identity_links
    from kestrel.policies.dataload import load_identity_rows
    from kestrel.testing import make_application, make_application_instance, make_connector_instance, make_organization

    org = make_organization(db_session)

    def account(app_type: ApplicationType, *, email: str, name: str, disabled: bool) -> Identity:
        from datetime import UTC, datetime

        from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

        application = make_application(db_session, org, application_type=app_type)
        app_instance = make_application_instance(db_session, org, application=application)
        connector_instance = make_connector_instance(db_session, org, application_instance=app_instance)
        db_session.flush()
        run = ConnectorRun(
            id=_uuid.uuid4(),
            org_id=org.id,
            connector_instance_id=connector_instance.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        db_session.add(run)
        db_session.flush()
        row = Identity(
            id=_uuid.uuid4(),
            org_id=org.id,
            application_instance_id=app_instance.id,
            provider_object_id=f"{app_type.value}-{_uuid.uuid4().hex[:8]}",
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

    okta = account(ApplicationType.OKTA, email="kj@acme.test", name="Katherine Johnson", disabled=True)
    slack = account(ApplicationType.SLACK, email="kj@acme.test", name="Katherine Johnson", disabled=False)
    rebuild_identity_links(db_session, org_id=org.id)

    rows = {row["_subject_id"]: row for row in load_identity_rows(db_session, org.id)}

    cluster = rows[slack.id]["cluster"]
    assert cluster["member_count"] == 2
    assert sorted(cluster["application_types"]) == ["okta", "slack"]
    # The person's IdP account is disabled while the Slack account is not:
    # exactly the departed-but-still-has-access shape.
    assert cluster["idp_status"] == "disabled"
    assert cluster["match_kind"] == "email"
    slack_account = next(a for a in cluster["accounts"] if a["identity_id"] == str(slack.id))
    okta_account = next(a for a in cluster["accounts"] if a["identity_id"] == str(okta.id))
    assert slack_account["is_disabled"] is False
    assert okta_account["is_disabled"] is True


def test_an_identity_with_no_idp_account_is_reported_absent(db_session):
    import uuid as _uuid
    from datetime import UTC, datetime

    from kestrel.db.models.application import ApplicationType
    from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
    from kestrel.db.models.identity import Identity, IdentityType
    from kestrel.identities.correlate import rebuild_identity_links
    from kestrel.policies.dataload import load_identity_rows
    from kestrel.testing import make_application, make_application_instance, make_connector_instance, make_organization

    org = make_organization(db_session)
    application = make_application(db_session, org, application_type=ApplicationType.GITHUB)
    app_instance = make_application_instance(db_session, org, application=application)
    connector_instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    run = ConnectorRun(
        id=_uuid.uuid4(),
        org_id=org.id,
        connector_instance_id=connector_instance.id,
        status=ConnectorRunStatus.SUCCESS,
        started_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.add(run)
    db_session.flush()
    local = Identity(
        id=_uuid.uuid4(),
        org_id=org.id,
        application_instance_id=app_instance.id,
        provider_object_id="gh-local",
        identity_type=IdentityType.USER,
        email="local.only@acme.test",
        display_name="Local Only",
        source_connector_run_id=run.id,
        raw_source={},
    )
    db_session.add(local)
    db_session.flush()
    rebuild_identity_links(db_session, org_id=org.id)

    rows = {row["_subject_id"]: row for row in load_identity_rows(db_session, org.id)}

    assert rows[local.id]["cluster"]["idp_status"] == "absent"
    assert rows[local.id]["cluster"]["member_count"] == 1


def test_the_row_cache_serves_one_load_per_family(db_session):
    """Every policy of a resource type shares one load; the rows are the same
    objects the uncached loader would have produced."""
    from kestrel.policies.dataload import RowCache, load_rows
    from kestrel.testing import make_organization

    org = make_organization(db_session)
    db_session.flush()
    cache = RowCache(db_session, org.id)

    first = cache.rows("identities")
    second = cache.rows("identities")

    assert first is second
    assert [r["_subject_id"] for r in first] == [r["_subject_id"] for r in load_rows(db_session, org.id, "identities")]


def test_identity_rows_carry_the_oauth_grants_the_account_authorized(db_session):
    """A consented token is a credential that survives disabling the account.

    Nothing joined the two before: the OAuth loader aggregates grants per
    application, so `who authorized this` was not reachable from a policy at
    all. `cross-app-oauth-grant-outlives-account` needs it per account.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from kestrel.db.models.application import ApplicationType
    from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
    from kestrel.db.models.identity import Identity, IdentityType
    from kestrel.db.models.oauth import OAuthApplication, OAuthGrant, OAuthScope
    from kestrel.policies.dataload import load_identity_rows
    from kestrel.testing import make_application, make_application_instance, make_connector_instance, make_organization

    org = make_organization(db_session)
    application = make_application(db_session, org, application_type=ApplicationType.GOOGLE_WORKSPACE)
    app_instance = make_application_instance(db_session, org, application=application)
    connector_instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    run = ConnectorRun(
        id=_uuid.uuid4(),
        org_id=org.id,
        connector_instance_id=connector_instance.id,
        status=ConnectorRunStatus.SUCCESS,
        started_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.add(run)
    db_session.flush()

    def identity(email: str, *, disabled: bool) -> Identity:
        row = Identity(
            id=_uuid.uuid4(),
            org_id=org.id,
            application_instance_id=app_instance.id,
            provider_object_id=f"gws-{_uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=email,
            display_name=email,
            is_disabled=disabled,
            source_connector_run_id=run.id,
            raw_source={},
        )
        db_session.add(row)
        db_session.flush()
        return row

    departed = identity("rf@acme.test", disabled=True)
    staying = identity("grace@acme.test", disabled=False)
    ungranted = identity("nobody@acme.test", disabled=False)

    oauth_app = OAuthApplication(
        id=_uuid.uuid4(),
        org_id=org.id,
        application_instance_id=app_instance.id,
        provider_object_id="analytics-sync",
        name="Analytics Sync",
        publisher="Third Party Ltd",
        is_verified=False,
        source_connector_run_id=run.id,
        raw_source={},
    )
    db_session.add(oauth_app)
    db_session.flush()
    db_session.add(
        OAuthScope(
            id=_uuid.uuid4(),
            org_id=org.id,
            oauth_application_id=oauth_app.id,
            scope_name="https://www.googleapis.com/auth/drive",
            is_sensitive=True,
        )
    )
    for holder in (departed, staying):
        db_session.add(
            OAuthGrant(
                id=_uuid.uuid4(),
                org_id=org.id,
                oauth_application_id=oauth_app.id,
                identity_id=holder.id,
                granted_at=datetime.now(UTC),
                source_connector_run_id=run.id,
            )
        )
    db_session.flush()

    rows = {row["_subject_id"]: row for row in load_identity_rows(db_session, org.id)}

    grants = rows[departed.id]["oauth_grants"]
    assert [grant["oauth_application_name"] for grant in grants] == ["Analytics Sync"]
    assert grants[0]["sensitive_scope_names"] == ["https://www.googleapis.com/auth/drive"]
    assert grants[0]["is_verified"] is False
    # Attached per account, not per application: the other holder gets their
    # own copy and an account with no grants gets an empty list, never None.
    assert len(rows[staying.id]["oauth_grants"]) == 1
    assert rows[ungranted.id]["oauth_grants"] == []
