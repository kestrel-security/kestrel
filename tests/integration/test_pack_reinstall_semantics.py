# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- re-installing a pack respects what the operator already decided.

An upgrade must not quietly re-enable a policy the operator turned off, must
not take over a custom policy that happens to share a slug, and must stop
evaluating policies the pack no longer ships.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.policies.packs import install_pack, retire_missing_packs
from kestrel.testing.factories import make_organization
from sqlalchemy.orm import Session

_POLICY = """\
POLICY_ID = "{slug}"
TITLE = "{slug}"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Identities without MFA."
REMEDIATION = "Require MFA."

def policy(resource):
    identity = resource.get("identity") or {{}}
    return bool(identity.get("mfa_enabled")){suffix}
"""


def _write_pack(root: Path, slugs: list[str], *, suffix: str = "") -> Path:
    pack = root / "testpack"
    policies = pack / "policies"
    policies.mkdir(parents=True, exist_ok=True)
    for stale in policies.glob("*.py"):
        stale.unlink()
    for slug in slugs:
        (policies / f"{slug.replace('-', '_')}.py").write_text(_POLICY.format(slug=slug, suffix=suffix))
    (pack / "pack.yaml").write_text(
        "name: testpack\nversion: '0.1.0'\ndescription: test\napplication: custom\npolicies:\n"
        + "".join(f"  - {slug}\n" for slug in slugs)
    )
    return pack


def _current_version(db_session: Session, policy: Policy) -> PolicyVersion:
    version = db_session.get(PolicyVersion, policy.current_version_id)
    assert version is not None
    return version


def test_reinstall_keeps_a_disabled_policy_disabled(db_session: Session, tmp_path: Path):
    org = make_organization(db_session)
    pack = _write_pack(tmp_path, ["tp-one", "tp-two"])
    first = {p.slug: p for p in install_pack(db_session, org.id, pack)}
    _current_version(db_session, first["tp-one"]).is_enabled = False
    db_session.flush()

    # Same source: no new version, still disabled.
    again = {p.slug: p for p in install_pack(db_session, org.id, pack)}
    assert _current_version(db_session, again["tp-one"]).is_enabled is False
    assert _current_version(db_session, again["tp-two"]).is_enabled is True

    # Changed source: a new version is written, and it inherits the choice.
    _write_pack(tmp_path, ["tp-one", "tp-two"], suffix="  # v2")
    upgraded = {p.slug: p for p in install_pack(db_session, org.id, pack)}
    one = _current_version(db_session, upgraded["tp-one"])
    assert one.version == 2
    assert one.is_enabled is False
    assert _current_version(db_session, upgraded["tp-two"]).is_enabled is True


def test_reinstall_retires_policies_the_pack_no_longer_ships(db_session: Session, tmp_path: Path):
    org = make_organization(db_session)
    pack = _write_pack(tmp_path, ["tp-one", "tp-two"])
    first = {p.slug: p for p in install_pack(db_session, org.id, pack)}

    _write_pack(tmp_path, ["tp-one"])
    installed = install_pack(db_session, org.id, pack)

    assert [p.slug for p in installed] == ["tp-one"]
    db_session.refresh(first["tp-two"])
    assert first["tp-two"].pack_name == "testpack"  # the row stays, for history
    assert _current_version(db_session, first["tp-two"]).is_enabled is False
    assert _current_version(db_session, first["tp-one"]).is_enabled is True


def test_install_refuses_to_adopt_a_custom_policy_with_the_same_slug(db_session: Session, tmp_path: Path):
    org = make_organization(db_session)
    custom = Policy(id=uuid.uuid4(), org_id=org.id, slug="tp-one", title="Mine", source=PolicySource.CUSTOM, pack_name=None)
    db_session.add(custom)
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=custom.id,
        version=1,
        source_text=_POLICY.format(slug="tp-one", suffix=""),
        severity=Severity("high"),
        is_enabled=True,
    )
    db_session.add(version)
    db_session.flush()
    custom.current_version_id = version.id
    db_session.flush()

    with pytest.raises(ValueError, match="custom policy with that slug already exists"):
        install_pack(db_session, org.id, _write_pack(tmp_path, ["tp-one"]))

    db_session.refresh(custom)
    assert custom.source == PolicySource.CUSTOM
    assert custom.pack_name is None


def test_a_pack_removed_from_the_catalog_is_retired_but_kept(db_session: Session, tmp_path: Path):
    """A pack deleted outright is never reinstalled, so the per-pack retire
    never visits it. Its rows stay (findings point at them); evaluation stops."""
    org = make_organization(db_session)
    catalog = tmp_path / "catalog"
    gone = {p.slug: p for p in install_pack(db_session, org.id, _write_pack(catalog, ["tp-gone"]))}
    (catalog / "testpack" / "pack.yaml").unlink()
    kept = _write_pack(tmp_path / "other", ["tp-kept"])
    (kept / "pack.yaml").write_text(
        "name: keptpack\nversion: '0.1.0'\ndescription: test\napplication: custom\npolicies:\n  - tp-kept\n"
    )
    kept_policy = install_pack(db_session, org.id, kept)[0]
    (catalog / "keptpack").symlink_to(kept, target_is_directory=True)

    assert retire_missing_packs(db_session, org.id, catalog) == 1
    assert retire_missing_packs(db_session, org.id, catalog) == 0

    assert db_session.get(Policy, gone["tp-gone"].id) is not None
    assert _current_version(db_session, gone["tp-gone"]).is_enabled is False
    assert _current_version(db_session, kept_policy).is_enabled is True
