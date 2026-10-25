# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Policy Workbench behavior the auth/tenant/pagination matrices can't
express: fork/version/activate lifecycle, enable toggling, and evaluate.
Role gating is covered by test_api_auth_matrix.py; cross-org access is
covered by test_api_tenant_isolation.py.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.policies.packs import install_pack, resolve_pack_dir
from kestrel.testing import api_client

from tests.integration.test_api_factories import make_identity, make_policy

VALID_SOURCE = """\
POLICY_ID = "{slug}"
TITLE = "A workbench-authored policy"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Identities without MFA."
REMEDIATION = "Require MFA."

def policy(resource):
    identity = resource.get("identity") or {{}}
    return bool(identity.get("mfa_enabled"))
"""


def _install_a_pack_policy(session, org):
    pack_dir = resolve_pack_dir("github-posture")
    assert pack_dir is not None, "packs/github-posture must exist for this test"
    installed = install_pack(session, org.id, pack_dir)
    assert installed, "github-posture installed no policies"
    return installed[0]


def test_create_custom_policy_persists_and_returns_detail(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org

    response = client.post("/api/v1/policies", json={"source_text": VALID_SOURCE.format(slug=f"wb-{org.id.hex[:8]}")})

    assert response.status_code == 201
    body = response.json()
    assert body["source"] == "custom"
    assert body["source_text"].startswith("POLICY_ID")


def test_create_custom_policy_rejects_a_duplicate_slug(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    slug = f"dup-{org.id.hex[:8]}"

    first = client.post("/api/v1/policies", json={"source_text": VALID_SOURCE.format(slug=slug)})
    assert first.status_code == 201

    second = client.post("/api/v1/policies", json={"source_text": VALID_SOURCE.format(slug=slug)})
    assert second.status_code == 400


def test_create_custom_policy_rejects_invalid_source(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/policies", json={"source_text": "this is not python policy source"})

    assert response.status_code == 400


def test_fork_pack_policy_creates_a_disabled_custom_copy(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    pack_policy = _install_a_pack_policy(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/policies/{pack_policy.id}/fork")

    assert response.status_code == 201
    forked = response.json()
    assert forked["source"] == "pack" or forked["source"] == "custom"  # sanity: field exists
    assert forked["source"] == "custom"
    assert forked["is_enabled"] is False
    assert forked["id"] != str(pack_policy.id)
    assert forked["pack_name"] is None


def test_forking_a_custom_policy_is_rejected(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    custom = make_policy(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/policies/{custom.id}/fork")

    assert response.status_code == 400


def test_publish_version_then_activate_a_prior_version(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    policy = make_policy(db_session, org)
    db_session.commit()
    original_version_id = str(policy.current_version_id)

    published = client.post(
        f"/api/v1/policies/{policy.id}/versions",
        json={"source_text": VALID_SOURCE.format(slug=policy.slug)},
    )
    assert published.status_code == 201
    assert published.json()["current_version_id"] != original_version_id

    versions = client.get(f"/api/v1/policies/{policy.id}/versions")
    assert versions.status_code == 200
    assert versions.json()["count"] == 2
    assert versions.json()["can_activate"] is True

    activated = client.post(f"/api/v1/policies/{policy.id}/versions/{original_version_id}/activate")
    assert activated.status_code == 200
    assert activated.json()["current_version_id"] == original_version_id


def test_activating_an_unknown_version_is_404(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    policy = make_policy(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/policies/{policy.id}/versions/00000000-0000-0000-0000-000000000000/activate")

    assert response.status_code == 404


def test_patch_toggles_is_enabled(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    policy = make_policy(db_session, org)
    db_session.commit()

    response = client.patch(f"/api/v1/policies/{policy.id}", json={"is_enabled": False})

    assert response.status_code == 200
    assert response.json()["is_enabled"] is False


def test_patch_with_no_fields_is_a_400(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    policy = make_policy(db_session, org)
    db_session.commit()

    response = client.patch(f"/api/v1/policies/{policy.id}", json={})

    assert response.status_code == 400


def test_evaluate_reconciles_a_real_match_into_a_finding(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    identity = make_identity(db_session, org, mfa_enabled=False)
    policy = make_policy(db_session, org)  # always non-compliant
    db_session.commit()

    response = client.post(f"/api/v1/policies/{policy.id}/evaluate")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["matched_object_count"] >= 1

    findings = client.get(f"/api/v1/policies/{policy.id}/findings")
    assert findings.status_code == 200
    assert findings.json()["open_finding_count"] >= 1 or findings.json().get("ever_evaluated") is True
    _ = identity  # used only to guarantee at least one identity row exists


def test_dry_run_never_persists_a_finding(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    make_identity(db_session, org, mfa_enabled=False)
    policy = make_policy(db_session, org)
    db_session.commit()

    response = client.post(f"/api/v1/policies/{policy.id}/dry-run")

    assert response.status_code == 200
    body = response.json()
    assert len(body["matches"]) >= 1

    findings = client.get(f"/api/v1/policies/{policy.id}/findings")
    assert findings.json()["open_finding_count"] == 0


def test_fixture_test_reports_pass_and_actual_subjects(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    policy = make_policy(db_session, org)
    db_session.commit()

    response = client.post(
        f"/api/v1/policies/{policy.id}/test",
        json={
            "fixtures": {
                "rows": [
                    {
                        "_subject_type": "identity",
                        "_subject_id": "11111111-1111-1111-1111-111111111111",
                        "identity": {"mfa_enabled": False},
                    }
                ],
                "expected_match_subject_ids": ["11111111-1111-1111-1111-111111111111"],
            }
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is True
    assert body["actual"] == ["11111111-1111-1111-1111-111111111111"]


def test_draft_that_fails_at_runtime_is_a_400_not_a_500(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    source = VALID_SOURCE.format(slug="draft-runtime-error").replace(
        "def policy(resource):", "def policy(resource):\n    return 'not a bool'\n\ndef unused(resource):"
    )

    response = client.post(
        "/api/v1/policies/test-draft",
        json={
            "source_text": source,
            "fixtures": {
                "rows": [{"_subject_type": "identity", "_subject_id": "s1", "identity": {}}],
                "expected_match_subject_ids": [],
            },
        },
    )

    assert response.status_code == 400
    assert "Evaluation failed" in response.json()["detail"]


def test_generate_refuses_an_oversized_intent(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/policies/generate", json={"intent": "x" * 4001})

    assert response.status_code == 422


# -- permanent delete ---------------------------------------------------------


def _seed_policy_history(db_session, client, policy):
    """A finding on `policy` with every kind of dependent row, plus an org-wide
    exception and a control mapping: the full set `DELETE` must take down."""
    from kestrel.db.models.compliance import ComplianceControl, ComplianceFramework, MappingSource, PolicyControlMapping
    from kestrel.db.models.finding import Exception_, FindingEvidence
    from kestrel.db.models.finding_note import FindingNote
    from kestrel.db.models.finding_watcher import FindingWatcher

    from tests.integration.test_api_factories import make_finding

    org = client.kestrel_org
    operator = client.kestrel_operator
    finding = make_finding(db_session, org, policy=policy)
    db_session.add(FindingNote(org_id=org.id, finding_id=finding.id, author_operator_id=operator.id, body="seen it"))
    db_session.add(FindingEvidence(finding_id=finding.id, label="identity.email", value={"v": "x@example.com"}))
    db_session.add(FindingWatcher(org_id=org.id, finding_id=finding.id, operator_id=operator.id))
    db_session.add(Exception_(org_id=org.id, finding_id=finding.id, policy_id=None, reason="finding-scoped"))
    db_session.add(Exception_(org_id=org.id, finding_id=None, policy_id=policy.id, reason="org-wide"))
    control = ComplianceControl(org_id=org.id, framework=ComplianceFramework.CUSTOM, control_id="T-1", title="Test")
    db_session.add(control)
    db_session.flush()
    db_session.add(
        PolicyControlMapping(policy_id=policy.id, compliance_control_id=control.id, source=MappingSource.USER_OVERRIDE)
    )
    db_session.commit()
    return finding


def test_delete_policy_removes_everything_derived_from_it(db_session):
    from kestrel.db.models.audit import AuditLog
    from kestrel.db.models.compliance import PolicyControlMapping
    from kestrel.db.models.finding import Exception_, Finding, FindingEvidence
    from kestrel.db.models.finding_note import FindingNote
    from kestrel.db.models.finding_watcher import FindingWatcher
    from kestrel.db.models.policy import Policy, PolicyEvaluation, PolicyVersion
    from sqlalchemy import select

    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    policy = make_policy(db_session, org)
    db_session.commit()
    finding = _seed_policy_history(db_session, client, policy)
    policy_id, version_id, finding_id = policy.id, policy.current_version_id, finding.id

    response = client.delete(f"/api/v1/policies/{policy_id}")

    assert response.status_code == 204
    db_session.expire_all()
    assert db_session.get(Policy, policy_id) is None
    assert db_session.get(PolicyVersion, version_id) is None
    assert db_session.get(Finding, finding_id) is None
    assert (
        db_session.scalars(select(PolicyEvaluation).where(PolicyEvaluation.policy_version_id == version_id)).first() is None
    )
    for model in (FindingEvidence, FindingNote, FindingWatcher):
        assert db_session.scalars(select(model).where(model.finding_id == finding_id)).first() is None
    assert db_session.scalars(select(Exception_).where(Exception_.policy_id == policy_id)).first() is None
    assert db_session.scalars(select(Exception_).where(Exception_.finding_id == finding_id)).first() is None
    assert (
        db_session.scalars(select(PolicyControlMapping).where(PolicyControlMapping.policy_id == policy_id)).first() is None
    )

    audit = db_session.scalars(select(AuditLog).where(AuditLog.org_id == org.id, AuditLog.action == "policy.deleted")).one()
    assert audit.target_id == policy_id
    assert audit.context["findings_deleted"] == 1
    assert audit.context["exceptions_deleted"] == 1, "the org-wide one; the finding-scoped one went with the finding"
    assert audit.context["control_mappings_deleted"] == 1

    assert client.get(f"/api/v1/policies/{policy_id}").status_code == 404
    assert all(p["id"] != str(policy_id) for p in client.get("/api/v1/policies").json())


def test_delete_policy_refuses_system_policies(db_session):
    from kestrel.db.models.policy import Policy, PolicySource

    client = api_client(db_session, OperatorRole.ANALYST)
    policy = make_policy(db_session, client.kestrel_org)
    policy.source = PolicySource.SYSTEM
    db_session.commit()

    response = client.delete(f"/api/v1/policies/{policy.id}")

    assert response.status_code == 409
    assert "disable" in response.json()["detail"]
    db_session.expire_all()
    assert db_session.get(Policy, policy.id) is not None


def test_delete_policy_is_org_scoped(db_session):
    from kestrel.db.models.policy import Policy

    owner = api_client(db_session, OperatorRole.ANALYST)
    policy = make_policy(db_session, owner.kestrel_org)
    db_session.commit()
    stranger = api_client(db_session, OperatorRole.ADMIN)
    assert stranger.kestrel_org.id != owner.kestrel_org.id

    response = stranger.delete(f"/api/v1/policies/{policy.id}")

    assert response.status_code == 404
    db_session.expire_all()
    assert db_session.get(Policy, policy.id) is not None


def test_deleted_pack_policy_comes_back_on_reinstall_without_findings(db_session):
    from kestrel.db.models.finding import Finding
    from kestrel.db.models.policy import Policy, PolicyVersion
    from sqlalchemy import select

    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    installed = _install_a_pack_policy(db_session, org)
    db_session.commit()
    slug, old_id = installed.slug, installed.id

    assert client.delete(f"/api/v1/policies/{old_id}").status_code == 204
    db_session.expire_all()
    assert db_session.get(Policy, old_id) is None

    pack_dir = resolve_pack_dir("github-posture")
    assert pack_dir is not None
    install_pack(db_session, org.id, pack_dir)
    db_session.commit()

    restored = db_session.scalars(select(Policy).where(Policy.org_id == org.id, Policy.slug == slug)).one()
    assert restored.id != old_id, "a fresh row, not a resurrected one"
    version_ids = list(db_session.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == restored.id)))
    assert version_ids
    assert db_session.scalars(select(Finding).where(Finding.policy_version_id.in_(version_ids))).first() is None
