# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""GitOps export -> plan -> apply against a real session, plus the CLI wrapper.

Every pack, policy and connector here is built inline under ``tmp_path``; no
shipped pack is referenced.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from kestrel.cli import gitops as gitops_cli
from kestrel.connectors.authoring import create_connector_instance
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorSecret
from kestrel.db.models.finding import Exception_
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion
from kestrel.gitops import apply_manifest, compute_plan, export_org_state, load_manifest
from kestrel.gitops.manifest import ConnectorSpec, DesiredState, ExceptionSpec, PackSpec, PolicySpec
from kestrel.policies.authoring import create_custom_policy
from kestrel.policies.packs import install_pack
from kestrel.secrets.store import set_secret
from kestrel.testing.factories import make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

POLICY_SOURCE = """
POLICY_ID = "{slug}"
TITLE = "{title}"
SEVERITY = "low"
RESOURCE_TYPE = "identity"


def policy(resource):
    return False
"""


def _source(slug: str, title: str = "GitOps test policy") -> str:
    return POLICY_SOURCE.format(slug=slug, title=title)


def _slug(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _make_pack(root: Path, name: str, slugs: list[str]) -> Path:
    pack_dir = root / name
    (pack_dir / "policies").mkdir(parents=True)
    (pack_dir / "pack.yaml").write_text(
        yaml.safe_dump({"name": name, "version": "1.0.0", "description": "test pack", "policies": slugs})
    )
    for slug in slugs:
        (pack_dir / "policies" / f"{slug.replace('-', '_')}.py").write_text(_source(slug))
    return pack_dir


def _changes(plan: Any) -> dict[tuple[str, str], Any]:
    return {(c.kind, c.identity): c for c in plan.changes}


def _actionable(plan: Any) -> list[tuple[str, str, str]]:
    return sorted((c.kind, c.identity, c.action) for c in plan.changes if c.action != "noop")


@pytest.fixture
def org(db_session: Session) -> Organization:
    return make_organization(db_session)


def _seed_world(session: Session, org: Organization, packs_root: Path) -> dict[str, Any]:
    pack_name = _slug("gitops-pack")
    pack_slug = _slug("gitops-pack-pol")
    pack_dir = _make_pack(packs_root, pack_name, [pack_slug])
    install_pack(session, org.id, pack_dir)

    custom_slug = _slug("gitops-custom")
    custom = create_custom_policy(session, org_id=org.id, source_text=_source(custom_slug))

    instance = create_connector_instance(
        session,
        org_id=org.id,
        connector_name="github",
        display_name="GitOps GitHub",
        external_tenant_ref="acme",
        config={"org_login": "acme", "org_domain": "a.example.com"},
        auth_method="pat",
        schedule_cron="0 * * * *",
    )
    set_secret(
        session,
        org_id=org.id,
        connector_instance_id=instance.id,
        field_name="token",
        plaintext_value="ghp_super_secret_value",
    )
    session.add(
        Exception_(
            id=uuid.uuid4(),
            org_id=org.id,
            policy_id=custom.id,
            finding_id=None,
            reason="accepted risk",
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )
    )
    session.flush()
    return {
        "pack_name": pack_name,
        "pack_dir": pack_dir,
        "pack_slug": pack_slug,
        "custom_slug": custom_slug,
        "custom": custom,
        "instance": instance,
    }


# --------------------------------------------------------------------------- export / round trip


def test_export_writes_manifest_and_never_secret_values(db_session: Session, org: Organization, tmp_path: Path) -> None:
    world = _seed_world(db_session, org, tmp_path / "packs")
    out = tmp_path / "out"

    state = export_org_state(db_session, org.id, out)

    text = (out / "kestrel.yaml").read_text()
    assert "ghp_super_secret_value" not in text
    raw = yaml.safe_load(text)
    assert raw["packs"] == [{"id": world["pack_name"]}]
    custom_file = f"policies/{world['custom_slug'].replace('-', '_')}.py"
    assert raw["policies"] == [{"path": custom_file, "enabled": True}]
    assert (out / custom_file).read_text() == _source(world["custom_slug"])
    (conn,) = raw["connectors"]
    assert conn["name"] == "GitOps GitHub"
    assert conn["type"] == "github"
    assert conn["schedule_cron"] == "0 * * * *"
    assert conn["secrets"] == [{"field": "token", "ref": "secret:token"}]
    assert raw["exceptions"] == [
        {"policy": world["custom_slug"], "reason": "accepted risk", "expires_at": "2030-01-01T00:00:00+00:00"}
    ]
    assert state.exceptions[0].policy == world["custom_slug"]


def test_round_trip_export_plan_modify_apply(
    db_session: Session, org: Organization, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packs_root = tmp_path / "packs"
    world = _seed_world(db_session, org, packs_root)
    monkeypatch.setenv("KESTREL_PACKS_DIR", str(packs_root))
    out = tmp_path / "out"
    export_org_state(db_session, org.id, out)

    # 1. A fresh export plans clean.
    plan = compute_plan(db_session, org.id, load_manifest(out))
    assert plan.errors == []
    assert _actionable(plan) == []
    assert plan.exit_code == 0
    assert plan.unmanaged == []

    # 2. Modify the manifest: edit a policy, disable it, change connector
    #    config/schedule, move an exception expiry, add a new policy+exception.
    raw = yaml.safe_load((out / "kestrel.yaml").read_text())
    custom_slug = world["custom_slug"]
    custom_path = out / raw["policies"][0]["path"]
    custom_path.write_text(_source(custom_slug, title="Edited title"))
    raw["policies"][0]["enabled"] = False

    new_slug = _slug("gitops-new")
    (out / "policies" / "new_policy.py").write_text(_source(new_slug))
    raw["policies"].append({"path": "policies/new_policy.py", "enabled": True})

    raw["connectors"][0]["config"]["org_login"] = "acme-renamed"
    raw["connectors"][0]["schedule_cron"] = "30 2 * * *"
    raw["exceptions"][0]["expires_at"] = "2031-06-01T00:00:00Z"
    raw["exceptions"].append({"policy": new_slug, "reason": "new policy accepted"})
    (out / "kestrel.yaml").write_text(yaml.safe_dump(raw, sort_keys=False))

    desired = load_manifest(out)
    plan = compute_plan(db_session, org.id, desired)
    assert plan.errors == []
    assert _actionable(plan) == [
        ("connector", "GitOps GitHub", "update"),
        ("exception", f"{custom_slug}:accepted risk", "update"),
        ("exception", f"{new_slug}:new policy accepted", "create"),
        ("policy", custom_slug, "update"),
        ("policy", new_slug, "create"),
    ]
    by_key = _changes(plan)
    assert by_key[("policy", custom_slug)].details == {
        "source": "changed",
        "enabled": {"from": True, "to": False},
    }
    conn_details = by_key[("connector", "GitOps GitHub")].details
    assert conn_details["config"] == "changed"
    assert conn_details["schedule_cron"] == {"from": "0 * * * *", "to": "30 2 * * *"}
    assert by_key[("exception", f"{new_slug}:new policy accepted")].details == {"policy_missing": True}
    assert by_key[("exception", f"{custom_slug}:accepted risk")].details["expires_at"]["to"] == "2031-06-01T00:00:00Z"
    assert by_key[("pack", world["pack_name"])].action == "noop"

    # 3. Dry run reports the same actions but writes nothing.
    dry = apply_manifest(db_session, org.id, desired, dry_run=True)
    assert dry.ok
    assert all(item["dry_run"] for item in dry.applied)
    assert len(dry.applied) == 5
    assert db_session.scalars(select(Policy).where(Policy.slug == new_slug)).one_or_none() is None

    # 4. Apply.
    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == []
    applied = sorted((a["kind"], a["identity"], a["action"]) for a in result.applied)
    assert applied == [
        ("connector", "GitOps GitHub", "update"),
        ("exception", f"{custom_slug}:accepted risk", "update"),
        ("exception", f"{new_slug}:new policy accepted", "create"),
        ("policy", custom_slug, "update"),
        ("policy", new_slug, "create"),
    ]
    assert {"kind": "pack", "identity": world["pack_name"], "action": "noop"} in result.skipped
    # The config change did not touch an endpoint key, so the secret survives.
    assert result.warnings == []
    db_session.flush()

    custom = world["custom"]
    version = db_session.get(PolicyVersion, custom.current_version_id)
    assert version is not None
    assert version.version == 2
    assert version.is_enabled is False
    assert custom.title == "Edited title"
    instance = world["instance"]
    assert instance.config["org_login"] == "acme-renamed"
    assert instance.schedule_cron == "30 2 * * *"
    assert db_session.scalars(select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance.id)).all(), (
        "non-endpoint config change must not clear secrets"
    )
    new_policy = db_session.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug == new_slug)).one()
    assert new_policy.source == PolicySource.CUSTOM
    exc = db_session.scalars(
        select(Exception_).where(Exception_.policy_id == new_policy.id, Exception_.finding_id.is_(None))
    ).one()
    assert exc.reason == "new policy accepted"
    assert exc.expires_at is None

    # 5. Plan is clean, and a second apply is a no-op.
    plan = compute_plan(db_session, org.id, desired)
    assert plan.errors == []
    assert _actionable(plan) == []
    again = apply_manifest(db_session, org.id, desired)
    assert again.ok
    assert again.applied == []


def test_plan_reports_unmanaged_resources(db_session: Session, org: Organization, tmp_path: Path) -> None:
    world = _seed_world(db_session, org, tmp_path / "packs")

    plan = compute_plan(db_session, org.id, DesiredState(base_dir=tmp_path))

    assert plan.changes == []
    assert plan.exit_code == 0
    assert sorted((u["kind"], u["identity"]) for u in plan.unmanaged) == sorted(
        [
            ("pack", world["pack_name"]),
            ("policy", world["custom_slug"]),
            ("connector", "GitOps GitHub"),
            ("exception", f"{world['custom_slug']}:accepted risk"),
        ]
    )
    assert "Unmanaged (present in DB" in plan.format_human()


# --------------------------------------------------------------------------- packs


def test_pack_by_path_create_then_update(db_session: Session, org: Organization, tmp_path: Path) -> None:
    pack_name = _slug("gitops-local")
    slugs = sorted([_slug("gitops-lp"), _slug("gitops-lp")])
    pack_dir = _make_pack(tmp_path, pack_name, slugs)
    desired = DesiredState(packs=[PackSpec(id=pack_name, path=pack_dir.name)], base_dir=tmp_path)

    plan = compute_plan(db_session, org.id, desired)
    (change,) = plan.changes
    assert (change.kind, change.identity, change.action) == ("pack", pack_name, "create")
    assert change.details == {"policies": dict.fromkeys(slugs, "missing")}

    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == []
    assert result.applied == [{"kind": "pack", "identity": pack_name, "action": "update", "policies": slugs}]
    assert compute_plan(db_session, org.id, desired).changes[0].action == "noop"

    # Edit one policy file in the pack -> update with source_changed.
    (pack_dir / "policies" / f"{slugs[0].replace('-', '_')}.py").write_text(_source(slugs[0], title="v2"))
    plan = compute_plan(db_session, org.id, desired)
    assert plan.changes[0].action == "update"
    assert plan.changes[0].details == {"policies": {slugs[0]: "source_changed"}}
    apply_manifest(db_session, org.id, desired)
    assert compute_plan(db_session, org.id, desired).changes[0].action == "noop"


def test_pack_policy_owned_elsewhere_is_metadata_drift(db_session: Session, org: Organization, tmp_path: Path) -> None:
    pack_name = _slug("gitops-meta")
    slug = _slug("gitops-meta-pol")
    pack_dir = _make_pack(tmp_path, pack_name, [slug])
    install_pack(db_session, org.id, pack_dir)
    policy = db_session.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug == slug)).one()
    policy.pack_name = "some-other-pack"
    db_session.flush()

    plan = compute_plan(db_session, org.id, DesiredState(packs=[PackSpec(path=pack_dir.name)], base_dir=tmp_path))
    assert plan.changes[0].action == "update"
    assert plan.changes[0].details == {"policies": {slug: "metadata"}}
    assert {"kind": "pack", "identity": "some-other-pack"} in plan.unmanaged


@pytest.mark.parametrize(
    ("spec_factory", "message"),
    [
        (lambda d: PackSpec(path="no-such-dir"), "has no pack.yaml"),
        (lambda d: PackSpec(id="wrong-name", path=d.name), "does not match pack.yaml name"),
        (lambda d: PackSpec(id="definitely-not-a-catalog-pack"), "not found in catalog"),
    ],
)
def test_pack_resolution_errors_surface_as_plan_errors(
    db_session: Session,
    org: Organization,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spec_factory: Any,
    message: str,
) -> None:
    monkeypatch.setenv("KESTREL_PACKS_DIR", str(tmp_path / "empty-catalog"))
    pack_dir = _make_pack(tmp_path, _slug("gitops-err"), [_slug("gitops-err-pol")])
    desired = DesiredState(packs=[spec_factory(pack_dir)], base_dir=tmp_path)

    plan = compute_plan(db_session, org.id, desired)
    assert plan.exit_code == 1
    assert len(plan.errors) == 1
    assert message in plan.errors[0]

    result = apply_manifest(db_session, org.id, desired)
    assert not result.ok
    assert result.errors == plan.errors


def test_pack_with_invalid_policy_reports_error(db_session: Session, org: Organization, tmp_path: Path) -> None:
    pack_name = _slug("gitops-bad")
    pack_dir = _make_pack(tmp_path, pack_name, [])
    (pack_dir / "policies" / "broken.py").write_text("def policy(:\n")

    plan = compute_plan(db_session, org.id, DesiredState(packs=[PackSpec(path=pack_dir.name)], base_dir=tmp_path))
    assert plan.changes == []
    assert len(plan.errors) == 1
    assert plan.errors[0].startswith(f"pack '{pack_name}' policy 'broken'")


# --------------------------------------------------------------------------- policies


def test_custom_policy_taking_over_pack_slug(db_session: Session, org: Organization, tmp_path: Path) -> None:
    pack_name = _slug("gitops-own")
    slug = _slug("gitops-own-pol")
    install_pack(db_session, org.id, _make_pack(tmp_path / "packs", pack_name, [slug]))
    (tmp_path / "mine.py").write_text(_source(slug, title="Now custom"))
    desired = DesiredState(policies=[PolicySpec(path="mine.py", slug=slug)], base_dir=tmp_path)

    change = _changes(compute_plan(db_session, org.id, desired))[("policy", slug)]
    assert change.action == "update"
    assert change.details["note"] == "will convert pack policy to custom on apply"

    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == []
    policy = db_session.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug == slug)).one()
    assert policy.source == PolicySource.CUSTOM
    assert policy.pack_name is None
    assert policy.title == "Now custom"
    assert _actionable(compute_plan(db_session, org.id, desired)) == []


def test_policy_colliding_with_system_policy_is_a_plan_error(db_session: Session, org: Organization, tmp_path: Path) -> None:
    slug = _slug("gitops-sys")
    db_session.add(
        Policy(id=uuid.uuid4(), org_id=org.id, slug=slug, title="System", source=PolicySource.SYSTEM, pack_name=None)
    )
    db_session.flush()
    (tmp_path / "sys.py").write_text(_source(slug))
    desired = DesiredState(policies=[PolicySpec(path="sys.py", slug=slug)], base_dir=tmp_path)

    plan = compute_plan(db_session, org.id, desired)
    assert plan.errors == [f"policy '{slug}' collides with a system policy"]
    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == plan.errors
    assert result.applied == []


def test_new_policy_can_be_created_disabled(db_session: Session, org: Organization, tmp_path: Path) -> None:
    slug = _slug("gitops-off")
    (tmp_path / "off.py").write_text(_source(slug))
    desired = DesiredState(policies=[PolicySpec(path="off.py", enabled=False, slug=slug)], base_dir=tmp_path)

    result = apply_manifest(db_session, org.id, desired)
    assert result.applied == [{"kind": "policy", "identity": slug, "action": "create"}]
    policy = db_session.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug == slug)).one()
    assert db_session.get(PolicyVersion, policy.current_version_id).is_enabled is False
    assert _actionable(compute_plan(db_session, org.id, desired)) == []


# --------------------------------------------------------------------------- connectors


def _connector_spec(**overrides: Any) -> ConnectorSpec:
    values: dict[str, Any] = {
        "name": "Applied GitHub",
        "type": "github",
        "external_tenant_ref": "acme",
        "config": {"org_login": "acme"},
    }
    values.update(overrides)
    return ConnectorSpec(**values)


def test_connector_create_warns_about_out_of_band_secrets(db_session: Session, org: Organization, tmp_path: Path) -> None:
    from kestrel.gitops.manifest import SecretRef

    spec = _connector_spec(secrets=[SecretRef(field="token", ref="env:GITHUB_TOKEN")], schedule_cron="0 3 * * *")
    desired = DesiredState(connectors=[spec], base_dir=tmp_path)

    change = _changes(compute_plan(db_session, org.id, desired))[("connector", "Applied GitHub")]
    assert change.action == "create"
    assert change.details == {"type": "github", "schedule_cron": "0 3 * * *"}

    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == []
    assert result.applied == [{"kind": "connector", "identity": "Applied GitHub", "action": "create"}]
    assert result.warnings == [
        "connector 'Applied GitHub' created without secrets (set out-of-band: token; refs=env:GITHUB_TOKEN)"
    ]
    instance_id = _instance_id(db_session, org, "Applied GitHub")
    assert (
        db_session.scalars(select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance_id)).all() == []
    )

    # Still drifting: the declared secret is not stored yet, and apply says so.
    plan = compute_plan(db_session, org.id, desired)
    change = _changes(plan)[("connector", "Applied GitHub")]
    assert change.action == "update"
    assert change.details == {"secrets_missing": ["token"]}
    again = apply_manifest(db_session, org.id, desired)
    assert any("still missing secret fields ['token']" in w for w in again.warnings)


def _instance_id(session: Session, org: Organization, name: str) -> uuid.UUID:
    app = session.scalars(
        select(ApplicationInstance).where(ApplicationInstance.org_id == org.id, ApplicationInstance.display_name == name)
    ).one()
    return session.scalars(select(ConnectorInstance).where(ConnectorInstance.application_instance_id == app.id)).one().id


def test_connector_extra_secrets_only_flagged_when_manifest_declares_secrets(
    db_session: Session, org: Organization, tmp_path: Path
) -> None:
    from kestrel.gitops.manifest import SecretRef

    world = _seed_world(db_session, org, tmp_path / "packs")
    base = {
        "name": "GitOps GitHub",
        "config": {"org_login": "acme", "org_domain": "a.example.com"},
        "schedule_cron": "0 * * * *",
    }
    without_secrets = DesiredState(connectors=[_connector_spec(**base)], base_dir=tmp_path)
    assert _changes(compute_plan(db_session, org.id, without_secrets))[("connector", "GitOps GitHub")].action == "noop"

    other_field = DesiredState(
        connectors=[_connector_spec(**base, secrets=[SecretRef(field="app_key", ref="env:K")])], base_dir=tmp_path
    )
    details = _changes(compute_plan(db_session, org.id, other_field))[("connector", "GitOps GitHub")].details
    assert details == {"secrets_missing": ["app_key"], "secrets_extra": ["token"]}
    assert world["instance"].id == _instance_id(db_session, org, "GitOps GitHub")


def test_connector_endpoint_change_clears_secrets(db_session: Session, org: Organization, tmp_path: Path) -> None:
    world = _seed_world(db_session, org, tmp_path / "packs")
    spec = _connector_spec(
        name="GitOps GitHub",
        external_tenant_ref="acme-moved",
        config={"org_login": "acme", "org_domain": "b.example.com"},
        sync_mode="live",
        schedule_cron=None,
    )
    desired = DesiredState(connectors=[spec], base_dir=tmp_path)

    details = _changes(compute_plan(db_session, org.id, desired))[("connector", "GitOps GitHub")].details
    assert details["external_tenant_ref"] == {"from": "acme", "to": "acme-moved"}
    assert details["sync_mode"] == {"from": "fixtures", "to": "live"}
    assert details["schedule_cron"] == {"from": "0 * * * *", "to": None}

    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == []
    assert result.warnings == [
        "connector 'GitOps GitHub': org_domain changed, so its stored secrets (token) were cleared; "
        "set them again via API/UI"
    ]
    instance = world["instance"]
    assert instance.sync_mode.value == "live"
    assert instance.schedule_cron is None
    assert (
        db_session.scalars(select(ConnectorSecret).where(ConnectorSecret.connector_instance_id == instance.id)).all() == []
    )
    app = db_session.get(ApplicationInstance, instance.application_instance_id)
    assert app.external_tenant_ref == "acme-moved"
    assert _actionable(compute_plan(db_session, org.id, desired)) == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"config": {"base_url": "http://127.0.0.1/api"}}, "non-public"),
        ({"schedule_cron": "not a cron"}, "connector 'Applied GitHub'"),
        ({"type": "no-such-connector"}, "is not installed"),
        ({"auth_method": "bogus"}, "Invalid auth_method"),
    ],
)
def test_connector_create_errors(
    db_session: Session, org: Organization, tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    desired = DesiredState(connectors=[_connector_spec(**overrides)], base_dir=tmp_path)
    result = apply_manifest(db_session, org.id, desired)
    assert result.applied == []
    assert len(result.errors) == 1
    assert message in result.errors[0]


def test_connector_update_rejects_type_change_and_bad_sync_mode(
    db_session: Session, org: Organization, tmp_path: Path
) -> None:
    _seed_world(db_session, org, tmp_path / "packs")
    base = {"name": "GitOps GitHub", "config": {"org_login": "acme", "org_domain": "a.example.com"}}

    type_change = DesiredState(connectors=[_connector_spec(**base, type="okta")], base_dir=tmp_path)
    details = _changes(compute_plan(db_session, org.id, type_change))[("connector", "GitOps GitHub")].details
    assert details["type"] == {"from": "github", "to": "okta"}
    result = apply_manifest(db_session, org.id, type_change)
    assert result.errors == ["connector 'GitOps GitHub' type mismatch (db=github, desired=okta); recreate manually"]

    bad_mode = DesiredState(connectors=[_connector_spec(**base, sync_mode="sideways")], base_dir=tmp_path)
    result = apply_manifest(db_session, org.id, bad_mode)
    assert len(result.errors) == 1
    assert "connector 'GitOps GitHub'" in result.errors[0]
    assert "sideways" in result.errors[0]


# --------------------------------------------------------------------------- policy-scoped exceptions


def test_policy_scoped_exceptions_create_update_and_ignore_finding_scoped(
    db_session: Session, org: Organization, tmp_path: Path
) -> None:
    slug = _slug("gitops-exc")
    policy = create_custom_policy(db_session, org_id=org.id, source_text=_source(slug))
    db_session.flush()
    desired = DesiredState(
        exceptions=[ExceptionSpec(policy=slug, reason="vendor managed", expires_at="2030-05-01T12:00:00")],
        base_dir=tmp_path,
    )

    (change,) = compute_plan(db_session, org.id, desired).changes
    assert (change.kind, change.action, change.details) == ("exception", "create", {})

    result = apply_manifest(db_session, org.id, desired)
    assert result.applied == [{"kind": "exception", "identity": f"{slug}:vendor managed", "action": "create"}]
    row = db_session.scalars(select(Exception_).where(Exception_.policy_id == policy.id)).one()
    assert row.finding_id is None
    # Naive timestamps are read as UTC.
    assert row.expires_at == datetime(2030, 5, 1, 12, tzinfo=UTC)
    assert compute_plan(db_session, org.id, desired).changes[0].action == "noop"

    # Removing the expiry is an update to an open-ended exception.
    open_ended = DesiredState(exceptions=[ExceptionSpec(policy=slug, reason="vendor managed")], base_dir=tmp_path)
    change = compute_plan(db_session, org.id, open_ended).changes[0]
    assert change.action == "update"
    assert change.details == {"expires_at": {"from": "2030-05-01T12:00:00+00:00", "to": None}}
    apply_manifest(db_session, org.id, open_ended)
    db_session.flush()
    assert row.expires_at is None
    assert compute_plan(db_session, org.id, open_ended).changes[0].action == "noop"


def test_exception_for_unknown_policy(db_session: Session, org: Organization, tmp_path: Path) -> None:
    desired = DesiredState(exceptions=[ExceptionSpec(policy="gitops-no-such-policy", reason="r")], base_dir=tmp_path)

    (change,) = compute_plan(db_session, org.id, desired).changes
    assert change.action == "create"
    assert change.details == {"policy_missing": True}

    result = apply_manifest(db_session, org.id, desired)
    assert result.errors == ["exception for unknown policy 'gitops-no-such-policy'"]


def test_exceptions_are_org_scoped(db_session: Session, org: Organization, tmp_path: Path) -> None:
    other = make_organization(db_session)
    slug = _slug("gitops-tenant")
    for o in (org, other):
        create_custom_policy(db_session, org_id=o.id, source_text=_source(slug))
    db_session.flush()
    desired = DesiredState(exceptions=[ExceptionSpec(policy=slug, reason="mine")], base_dir=tmp_path)
    apply_manifest(db_session, other.id, desired)

    # The other org's identical exception does not satisfy this org's plan.
    plan = compute_plan(db_session, org.id, desired)
    assert plan.changes[0].action == "create"
    assert plan.unmanaged == [{"kind": "policy", "identity": slug}]


# --------------------------------------------------------------------------- CLI


class _SharedSession:
    """The test session, minus close(): the CLI closes what it opens."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def close(self) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


@pytest.fixture
def cli(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    monkeypatch.setattr(gitops_cli, "get_sessionmaker", lambda: lambda: _SharedSession(db_session))
    return CliRunner()


def test_cli_without_organization_exits_1(cli: CliRunner, db_session: Session, tmp_path: Path) -> None:
    if db_session.scalars(select(Organization)).first() is not None:
        pytest.fail("worker database unexpectedly contains a committed organization")
    result = cli.invoke(gitops_cli.app, ["export", "--output", str(tmp_path / "out")])
    assert result.exit_code == 1
    assert "No organization configured" in result.output


def test_cli_export_plan_apply(cli: CliRunner, db_session: Session, org: Organization, tmp_path: Path) -> None:
    out = tmp_path / "out"
    slug = _slug("gitops-cli")
    create_custom_policy(db_session, org_id=org.id, source_text=_source(slug))
    db_session.flush()

    result = cli.invoke(gitops_cli.app, ["export", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "Wrote" in result.output

    result = cli.invoke(gitops_cli.app, ["plan", str(out)])
    assert result.exit_code == 0, result.output
    assert "no drift" in result.output

    raw = yaml.safe_load((out / "kestrel.yaml").read_text())
    raw["exceptions"] = [{"policy": slug, "reason": "cli exception"}]
    (out / "kestrel.yaml").write_text(yaml.safe_dump(raw))

    result = cli.invoke(gitops_cli.app, ["plan", str(out), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["in_sync"] is False
    assert [(c["kind"], c["action"]) for c in payload["changes"]] == [("policy", "noop"), ("exception", "create")]

    result = cli.invoke(gitops_cli.app, ["apply", str(out), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Dry-run complete" in result.output
    assert db_session.scalars(select(Exception_).where(Exception_.reason == "cli exception")).first() is None

    result = cli.invoke(gitops_cli.app, ["apply", str(out)])
    assert result.exit_code == 0, result.output
    assert "Apply complete" in result.output
    assert "+ {'kind': 'exception'" in result.output
    assert db_session.scalars(select(Exception_).where(Exception_.reason == "cli exception")).one()

    result = cli.invoke(gitops_cli.app, ["plan", str(out)])
    assert result.exit_code == 0, result.output


def test_cli_invalid_manifest_and_apply_errors(
    cli: CliRunner, db_session: Session, org: Organization, tmp_path: Path
) -> None:
    # The CLI rolls back on failure; commit (a savepoint release here) so the
    # org survives that rollback the way a real, committed org would.
    db_session.commit()
    (tmp_path / "kestrel.yaml").write_text("kind: Nope\n")
    for command in ("plan", "apply"):
        result = cli.invoke(gitops_cli.app, [command, str(tmp_path)])
        assert result.exit_code == 1
        assert "Unsupported kind" in result.output

    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "kestrel.yaml").write_text(yaml.safe_dump({"exceptions": [{"policy": "gitops-nope", "reason": "r"}]}))
    result = cli.invoke(gitops_cli.app, ["apply", str(bad)])
    assert result.exit_code == 1
    assert "exception for unknown policy 'gitops-nope'" in result.output
