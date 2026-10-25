# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Builds a FixtureTransport preconfigured for this connector's bundled
fixtures/ dataset (a synthetic "acme-corp" GitHub org), used by unit tests
and by `kestrel connector validate` to prove the connector works without live
credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

from kestrel.connectors.sdk.fixtures import FixtureStatus, FixtureTransport

from kestrel_connector_github.client import PER_PAGE, build_path

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"

ORG_LOGIN = "acme-corp"

# Retained for callers that import them (docs, tests). The mapping itself is
# derived from fixture *content* -- see `_slugs_and_names`.
TEAM_SLUGS = ["platform-team", "security-team"]
REPO_NAMES = ["web-app", "secrets-vault", "public-docs"]


def _load(fixtures_dir: Path, name: str) -> list[dict]:
    path = fixtures_dir / name
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else []


def _slugs_and_names(fixtures_dir: Path) -> tuple[list[str], list[str]]:
    """Team slugs and repo names read out of the fixture set itself.

    Deriving these instead of hardcoding them is what lets a *generated*
    fixture tree (the demo seed) reuse this mapping unchanged. It also removes
    a whole class of bug: a fixture file whose id was never added to a module
    constant is unreachable, and resolves to an empty response rather than
    failing, so the gap is invisible.
    """
    teams = [str(t["slug"]) for t in _load(fixtures_dir, "teams.json") if t.get("slug")]
    repos = [str(r["name"]) for r in _load(fixtures_dir, "repos.json") if r.get("name")]
    return (teams or list(TEAM_SLUGS)), (repos or list(REPO_NAMES))


def _mapping(org_login: str, fixtures_dir: Path) -> dict[str, str | FixtureStatus]:
    """Signatures are built from the same `build_path()` helper the client uses, so
    a query-string change in one place cannot silently desynchronize the
    fixture keys from the requests the collector actually makes."""
    pp = PER_PAGE
    team_slugs, repo_names = _slugs_and_names(fixtures_dir)
    mapping = {
        f"GET /orgs/{org_login}": "org.json",
        f"GET {build_path(f'/orgs/{org_login}/members', role='admin', per_page=pp)}": "members_admin.json",
        f"GET {build_path(f'/orgs/{org_login}/members', role='member', per_page=pp)}": "members_member.json",
        f"GET {build_path(f'/orgs/{org_login}/members', filter='2fa_disabled', per_page=pp)}": ("members_2fa_disabled.json"),
        f"GET {build_path(f'/orgs/{org_login}/teams', per_page=pp)}": "teams.json",
        f"GET {build_path(f'/orgs/{org_login}/repos', per_page=pp)}": "repos.json",
        f"GET {build_path(f'/orgs/{org_login}/outside_collaborators', per_page=pp)}": ("outside_collaborators.json"),
        f"GET {build_path(f'/orgs/{org_login}/audit-log', per_page=pp, include='web', order='asc')}": ("audit_log.json"),
        # -- org security surface --------------------------------
        f"GET /orgs/{org_login}/actions/permissions": "actions_permissions.json",
        f"GET /orgs/{org_login}/actions/permissions/workflow": ("actions_workflow_permissions.json"),
        f"GET {build_path(f'/orgs/{org_login}/actions/runner-groups', per_page=pp)}": ("runner_groups.json"),
        f"GET {build_path(f'/orgs/{org_login}/actions/runners', per_page=pp)}": ("self_hosted_runners.json"),
        f"GET {build_path(f'/orgs/{org_login}/actions/secrets', per_page=pp)}": ("actions_secrets.json"),
        f"GET {build_path(f'/orgs/{org_login}/actions/variables', per_page=pp)}": ("actions_variables.json"),
        f"GET {build_path(f'/orgs/{org_login}/hooks', per_page=pp)}": "org_webhooks.json",
        f"GET {build_path(f'/orgs/{org_login}/installations', per_page=pp)}": ("installations.json"),
        f"GET {build_path(f'/orgs/{org_login}/credential-authorizations', per_page=pp)}": ("credential_authorizations.json"),
        # GraphQL: SAML/SCIM identities per member (one page in fixtures). A
        # tree without the file reproduces GitHub's answer for an org that has
        # no SAML provider the token can read, which degrades, never fails.
        "POST /graphql": (
            "saml_external_identities.json"
            if (fixtures_dir / "saml_external_identities.json").exists()
            else FixtureStatus(404)
        ),
        f"GET {build_path(f'/orgs/{org_login}/rulesets', per_page=pp)}": "org_rulesets.json",
        f"GET /orgs/{org_login}/security-managers": "security_managers.json",
        f"GET {build_path(f'/orgs/{org_login}/organization-roles', per_page=pp)}": ("custom_org_roles.json"),
        f"GET {build_path(f'/orgs/{org_login}/invitations', per_page=pp)}": ("org_invitations.json"),
        f"GET {build_path(f'/orgs/{org_login}/personal-access-token-requests', per_page=pp)}": ("pat_requests.json"),
        # Extended coverage
        f"GET /orgs/{org_login}/copilot/billing": "copilot_policy.json",
        f"GET {build_path(f'/orgs/{org_login}/copilot/billing/seats', per_page=pp)}": "copilot_seats.json",
        f"GET {build_path(f'/orgs/{org_login}/personal-access-tokens', per_page=pp)}": "approved_pats.json",
        # Org packages: mapped per type for the types this connector collects.
        # The container fixture is present (a public package from a private repo)
        # to allow fixture-mode validation. The other types are empty, which is
        # what GitHub returns for a type the org has no packages of -- a 404
        # here marks the family skipped and every fixture sync partial.
        f"GET {build_path(f'/orgs/{org_login}/packages', package_type='container', per_page=pp)}": (
            "org_packages_container.json"
        ),
        f"GET {build_path(f'/orgs/{org_login}/packages', package_type='npm', per_page=pp)}": ("org_packages_empty.json"),
        f"GET {build_path(f'/orgs/{org_login}/packages', package_type='maven', per_page=pp)}": ("org_packages_empty.json"),
        f"GET {build_path(f'/orgs/{org_login}/packages', package_type='docker', per_page=pp)}": ("org_packages_empty.json"),
    }
    for slug in team_slugs:
        members = build_path(f"/orgs/{org_login}/teams/{slug}/members", per_page=pp)
        repos = build_path(f"/orgs/{org_login}/teams/{slug}/repos", per_page=pp)
        mapping[f"GET {members}"] = f"team_members_{slug}.json"
        mapping[f"GET {repos}"] = f"team_repos_{slug}.json"
    for repo_name in repo_names:
        collaborators = build_path(
            f"/repos/{org_login}/{repo_name}/collaborators",
            affiliation="direct",
            per_page=pp,
        )
        mapping[f"GET {collaborators}"] = f"repo_collaborators_{repo_name}.json"
        # -- per-repository posture ------------------------------
        # Branch protection is mapped only where the fixture exists: GitHub
        # 404s an unprotected branch, and an unmapped signature reproduces
        # that absence, which is the case the collector has to handle.
        repo_root = f"/repos/{org_login}/{repo_name}"
        protection_file = fixtures_dir / f"repo_branch_protection_{repo_name}.json"
        mapping[f"GET {repo_root}/branches/main/protection"] = (
            f"repo_branch_protection_{repo_name}.json" if protection_file.exists() else FixtureStatus(404)
        )
        mapping[f"GET {build_path(f'{repo_root}/rulesets', per_page=pp)}"] = f"repo_rulesets_{repo_name}.json"
        mapping[f"GET {build_path(f'{repo_root}/hooks', per_page=pp)}"] = f"repo_webhooks_{repo_name}.json"
        mapping[f"GET {build_path(f'{repo_root}/keys', per_page=pp)}"] = f"repo_deploy_keys_{repo_name}.json"
        mapping[f"GET {build_path(f'{repo_root}/environments', per_page=pp)}"] = f"repo_environments_{repo_name}.json"
        mapping[f"GET {repo_root}/actions/permissions"] = f"repo_actions_permissions_{repo_name}.json"
        mapping[f"GET {build_path(f'{repo_root}/secret-scanning/alerts', state='open', per_page=pp)}"] = (
            f"repo_secret_scanning_alerts_{repo_name}.json"
        )
        # Extended: additional per-repo posture. A missing file is a 404, the
        # same answer GitHub gives when the feature is not enabled, so generated
        # tenants that only add repositories still collect.
        dep_file = fixtures_dir / f"repo_dependabot_alerts_{repo_name}.json"
        mapping[f"GET {build_path(f'{repo_root}/dependabot/alerts', state='open', per_page=pp)}"] = (
            f"repo_dependabot_alerts_{repo_name}.json" if dep_file.exists() else FixtureStatus(404)
        )
        code_alerts_file = fixtures_dir / f"repo_code_scanning_alerts_{repo_name}.json"
        mapping[f"GET {build_path(f'{repo_root}/code-scanning/alerts', state='open', per_page=pp)}"] = (
            f"repo_code_scanning_alerts_{repo_name}.json" if code_alerts_file.exists() else FixtureStatus(404)
        )
        # Vulnerability alerts: GitHub answers 204 No Content when alerts are
        # enabled and 404 when they are not, which is the finding. The fixture
        # file is a marker only -- its presence means "enabled" and the
        # transport reproduces the empty 204 rather than reading it, so the
        # fixture path exercises the same no-body response live syncs see.
        vuln_file = fixtures_dir / f"repo_vulnerability_alerts_{repo_name}.json"
        mapping[f"GET {repo_root}/vulnerability-alerts"] = FixtureStatus(204) if vuln_file.exists() else FixtureStatus(404)
        code_scan_file = fixtures_dir / f"repo_code_scanning_setup_{repo_name}.json"
        mapping[f"GET {repo_root}/code-scanning/default-setup"] = (
            f"repo_code_scanning_setup_{repo_name}.json" if code_scan_file.exists() else FixtureStatus(404)
        )
    return mapping


def build_fixture_transport(org_login: str = ORG_LOGIN, fixtures_dir: str | Path | None = None) -> FixtureTransport:
    """`fixtures_dir` overrides the bundled dataset with an edited copy, which
    is how change-detection tests and the demo script stage a "someone changed
    something between syncs" tenant."""
    resolved = Path(fixtures_dir) if fixtures_dir else FIXTURES_DIR
    return FixtureTransport(
        fixtures_dir=resolved,
        mapping=_mapping(org_login, resolved),
        # An incremental audit-log poll appends `&phrase=created:>=<timestamp>`,
        # which changes every run and so cannot be an exact-match signature
        # .
        volatile_params={"phrase"},
    )
