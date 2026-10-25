# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- policy match -> Finding reconciliation (``findings.pipeline``).

Uses a tiny test-owned Python policy (RESOURCE_TYPE=identity) evaluated
against identities built directly with factories/ORM -- not a shipped pack,
so nothing here is coupled to a pack's fixture personas. The policy runtime
is whatever ``KESTREL_POLICY_RUNTIME`` the root conftest set (``restricted``
by default), same as production.
"""

from __future__ import annotations

import uuid

from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.findings.pipeline import evaluate_all_enabled_policies, evaluate_policy_version
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session

_POLICY_SOURCE = """
POLICY_ID = "test-identity-requires-mfa"
TITLE = "Identity requires MFA"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"


def policy(resource):
    identity = resource.get("identity") or {}
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {}
    return {"identity.email": identity.get("email")}
"""


class _World:
    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.connector_instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()
        self._run_id = self._new_connector_run_id()

    def _new_connector_run_id(self) -> uuid.UUID:
        from datetime import UTC, datetime

        from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=self.connector_instance.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        return run.id

    def identity(self, *, mfa_enabled: bool | None) -> Identity:
        row = Identity(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            provider_object_id=f"identity-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=f"{uuid.uuid4().hex[:8]}@example.test",
            display_name="Test Identity",
            mfa_enabled=mfa_enabled,
            source_connector_run_id=self._run_id,
            raw_source={},
        )
        self.session.add(row)
        self.session.flush()
        return row

    def policy_version(self, *, source_text: str = _POLICY_SOURCE, slug: str = "test-policy") -> PolicyVersion:
        policy = Policy(
            id=uuid.uuid4(),
            org_id=self.org.id,
            slug=f"{slug}-{uuid.uuid4().hex[:8]}",
            title="Identity requires MFA",
            source=PolicySource.CUSTOM,
        )
        self.session.add(policy)
        self.session.flush()

        version = PolicyVersion(
            id=uuid.uuid4(),
            policy_id=policy.id,
            version=1,
            source_text=source_text,
            severity=Severity.MEDIUM,
            compliance_mappings={},
            is_enabled=True,
        )
        self.session.add(version)
        self.session.flush()

        policy.current_version_id = version.id
        self.session.flush()
        return version

    def open_findings_for(self, policy_version: PolicyVersion) -> list[Finding]:
        # This session runs with autoflush=False (test isolation, see root
        # conftest), so a status change `_reconcile_findings` made in-memory
        # is invisible to a DB-level WHERE status = 'open' filter until
        # flushed -- exactly what a production session's autoflush (or the
        # caller's session.commit()) would otherwise do for free.
        self.session.flush()
        return list(
            self.session.scalars(
                select(Finding).where(
                    Finding.org_id == self.org.id,
                    Finding.policy_version_id == policy_version.id,
                    Finding.status == FindingStatus.OPEN,
                )
            ).all()
        )


def test_policy_match_opens_a_finding(db_session: Session):
    world = _World(db_session)
    identity = world.identity(mfa_enabled=False)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)

    findings = world.open_findings_for(policy_version)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.subject_type is FindingSubjectType.IDENTITY
    assert finding.subject_id == identity.id
    assert finding.status is FindingStatus.OPEN


def test_compliant_identity_never_opens_a_finding(db_session: Session):
    world = _World(db_session)
    world.identity(mfa_enabled=True)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)

    assert world.open_findings_for(policy_version) == []


def test_condition_clearing_auto_resolves_the_finding(db_session: Session):
    world = _World(db_session)
    identity = world.identity(mfa_enabled=False)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)
    findings = world.open_findings_for(policy_version)
    assert len(findings) == 1
    finding_id = findings[0].id

    identity.mfa_enabled = True
    db_session.flush()

    evaluate_policy_version(db_session, policy_version, world.org.id)

    assert world.open_findings_for(policy_version) == []
    resolved = db_session.get(Finding, finding_id)
    assert resolved is not None
    assert resolved.status is FindingStatus.RESOLVED
    assert resolved.resolved_at is not None


def test_a_tombstoned_subject_auto_resolves_its_finding(db_session: Session):
    """A departed identity must not keep its findings open: tombstoned rows are
    invisible to the policy loaders, so the next evaluation finds no match."""
    from datetime import UTC, datetime

    world = _World(db_session)
    identity = world.identity(mfa_enabled=False)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)
    assert len(world.open_findings_for(policy_version)) == 1

    identity.deleted_at = datetime.now(UTC)
    db_session.flush()

    evaluate_policy_version(db_session, policy_version, world.org.id)

    assert world.open_findings_for(policy_version) == []


def test_repeated_evaluation_with_a_persistent_match_reuses_the_same_finding_identity(db_session: Session):
    """The match reappearing across consecutive evaluations must update the
    one open Finding row, not create a new one each time (rule: assert
    structure/invariants, not a specific row count from one run)."""
    world = _World(db_session)
    world.identity(mfa_enabled=False)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)
    first_pass = world.open_findings_for(policy_version)
    assert len(first_pass) == 1
    finding_id = first_pass[0].id
    first_last_seen = first_pass[0].last_seen_at

    evaluate_policy_version(db_session, policy_version, world.org.id)
    evaluate_policy_version(db_session, policy_version, world.org.id)

    second_pass = world.open_findings_for(policy_version)
    assert len(second_pass) == 1
    assert second_pass[0].id == finding_id
    assert second_pass[0].last_seen_at >= first_last_seen


def test_no_concurrent_duplicate_open_finding_after_resolve_and_rematch(db_session: Session):
    """Resolve then re-trigger the same condition -- at any point in time
    there is at most one OPEN finding for a given (policy_version, subject)."""
    world = _World(db_session)
    identity = world.identity(mfa_enabled=False)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)
    assert len(world.open_findings_for(policy_version)) == 1

    identity.mfa_enabled = True
    db_session.flush()
    evaluate_policy_version(db_session, policy_version, world.org.id)
    assert world.open_findings_for(policy_version) == []

    identity.mfa_enabled = False
    db_session.flush()
    evaluate_policy_version(db_session, policy_version, world.org.id)

    open_again = world.open_findings_for(policy_version)
    assert len(open_again) == 1
    assert open_again[0].subject_id == identity.id


def test_two_identities_get_independent_findings(db_session: Session):
    world = _World(db_session)
    non_compliant = world.identity(mfa_enabled=False)
    world.identity(mfa_enabled=True)
    policy_version = world.policy_version()

    evaluate_policy_version(db_session, policy_version, world.org.id)

    findings = world.open_findings_for(policy_version)
    assert {f.subject_id for f in findings} == {non_compliant.id}


_REPO_POLICY_SOURCE = """
POLICY_ID = "test-repo-unprotected"
TITLE = "Repository default branch is unprotected"
SEVERITY = "high"
RESOURCE_TYPE = "resource"


def policy(resource):
    settings = resource.get("settings_by_key") or {}
    setting = settings.get("repo_default_branch_protected")
    if setting is None:
        return True
    return setting.get("value") is not False


def evidence(resource):
    repo = resource.get("resource") or {}
    return {"resource.name": repo.get("name")}
"""


def test_a_resource_policy_opens_a_finding_against_the_repository(db_session: Session):
    """`RESOURCE_TYPE = "resource"` end to end.

    The loader, `FindingSubjectType.RESOURCE`, and reconciliation all have to
    agree, or a repository policy evaluates and then records nothing. Nothing
    exercised that path before, because no policy could iterate repositories.
    """
    from kestrel.connectors.sdk.base import NormalizedObject
    from kestrel.sync.upsert import UpsertContext, upsert_provenance_objects

    world = _World(db_session)
    ctx = UpsertContext(
        org_id=world.org.id,
        application_instance_id=world.app_instance.id,
        connector_run_id=world._run_id,
        connector_instance_id=world.connector_instance.id,
    )
    upsert_provenance_objects(
        db_session,
        [
            NormalizedObject(
                kind="resource",
                provider_id="repo-1",
                attributes={
                    "resource_type": "repository",
                    "name": "web-app",
                    "visibility": "private",
                },
                raw_source={},
            ),
            NormalizedObject(
                kind="setting",
                provider_id="repo-setting:repo-1:repo_default_branch_protected",
                attributes={
                    "key": "repo_default_branch_protected",
                    "category": "security",
                    "label": "Default branch protection",
                    "value": False,
                    "value_type": "boolean",
                    "subject_type": "resource",
                    "subject_ref": "repo-1",
                },
                raw_source={},
            ),
        ],
        ctx,
    )
    db_session.flush()

    version = world.policy_version(source_text=_REPO_POLICY_SOURCE)
    evaluate_policy_version(db_session, org_id=world.org.id, policy_version=version)
    db_session.flush()

    findings = db_session.scalars(
        select(Finding).where(
            Finding.org_id == world.org.id,
            Finding.subject_type == FindingSubjectType.RESOURCE,
        )
    ).all()
    assert len(findings) == 1
    # The subject is the repository row itself, not the setting that failed.
    assert findings[0].subject_id is not None


_ALWAYS_MATCHES_SOURCE = """
POLICY_ID = "test-identity-is-admin"
TITLE = "Identity holds admin"
SEVERITY = "high"
RESOURCE_TYPE = "identity"


def policy(resource):
    return False
"""


def test_full_evaluation_reconciles_toxic_combinations_from_open_findings(db_session: Session):
    """Two open findings on one identity -- one privileged, one without MFA --
    combine into a system toxic-combination finding, which resolves once the
    contributing no-MFA finding does."""
    world = _World(db_session)
    identity = world.identity(mfa_enabled=False)
    world.policy_version(source_text=_ALWAYS_MATCHES_SOURCE, slug="test-admin")
    world.policy_version(slug="test-no-mfa")

    evaluate_all_enabled_policies(db_session, world.org.id)
    db_session.flush()

    toxic_policy = db_session.scalars(
        select(Policy).where(Policy.org_id == world.org.id, Policy.slug == "system-toxic-privileged-no-mfa")
    ).one()
    assert toxic_policy.source is PolicySource.SYSTEM
    toxic_version = db_session.get(PolicyVersion, toxic_policy.current_version_id)
    assert toxic_version is not None
    toxic = world.open_findings_for(toxic_version)
    assert [(f.subject_type, f.subject_id) for f in toxic] == [(FindingSubjectType.IDENTITY, identity.id)]

    identity.mfa_enabled = True
    db_session.flush()
    evaluate_all_enabled_policies(db_session, world.org.id)

    assert world.open_findings_for(toxic_version) == []
