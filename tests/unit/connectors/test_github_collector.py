# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for GitHubCollector's caching and degradation behaviour.

Both are load-bearing and neither was covered: four object types share two
expensive listings, and a plan-gated audit log used to fail the entire sync,
discarding members, teams, repos and grants that had already collected.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from kestrel_connector_github.client import GitHubClient
from kestrel_connector_github.collector import GitHubCollector

ORG = "acme"


def _http_error(status: int, headers: dict[str, str] | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.github.com/x")
    response = httpx.Response(status, headers=headers or {}, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


class _CountingTransport:
    """Counts paginate() calls per path prefix; raises canned errors."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def _lookup(self, path: str) -> Any:
        for prefix, value in sorted(self.responses.items(), key=lambda kv: -len(kv[0])):
            if path.startswith(prefix):
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(path)
        return self._lookup(path)

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(path)
        yield from self._lookup(path)


_TEAMS = [{"id": 5001, "slug": "platform", "name": "Platform"}]
_REPOS = [{"id": 9001, "name": "web-app", "private": True, "permissions": {}}]

_ORG_SURFACE = {
    f"/orgs/{ORG}/actions/permissions/workflow": {"default_workflow_permissions": "write"},
    f"/orgs/{ORG}/actions/permissions": {"allowed_actions": "all"},
    f"/orgs/{ORG}/actions/runner-groups": {"runner_groups": [{"id": 1, "name": "Default"}]},
    f"/orgs/{ORG}/actions/runners": {"runners": [{"id": 91, "name": "build-01"}]},
    f"/orgs/{ORG}/actions/secrets": {"secrets": [{"name": "DEPLOY_TOKEN", "visibility": "all"}]},
    f"/orgs/{ORG}/actions/variables": {"variables": [{"name": "LEGACY", "value": "super-secret", "visibility": "all"}]},
    f"/orgs/{ORG}/hooks": [
        {
            "id": 5501,
            "active": True,
            "events": ["push"],
            "config": {
                "url": "https://hooks.example.test/services/T0/B0/tok-en",
                "secret": "********",
                "insecure_ssl": "0",
            },
        }
    ],
    f"/orgs/{ORG}/installations": {"installations": [{"id": 7001, "app_slug": "bot"}]},
    f"/orgs/{ORG}/credential-authorizations": [{"credential_id": 1, "login": "dave"}],
    f"/orgs/{ORG}/rulesets": [{"id": 8801, "name": "main"}],
    f"/orgs/{ORG}/security-managers": [{"id": 5002, "slug": "security-team"}],
    f"/orgs/{ORG}/organization-roles": {"roles": [{"id": 9901, "name": "Custom"}]},
    f"/orgs/{ORG}/invitations": [{"id": 6601, "login": "newhire", "role": "admin"}],
    f"/orgs/{ORG}/personal-access-token-requests": [{"id": 7701, "owner": {"login": "dave"}}],
    # Extended coverage
    f"/orgs/{ORG}/copilot/billing": {"seat_management_setting": "assign_selected", "public_code_suggestions": "block"},
    f"/orgs/{ORG}/copilot/billing/seats": {"total_seats": 0, "seats": []},
    f"/orgs/{ORG}/personal-access-tokens": [],
    f"/orgs/{ORG}/packages": [],
}


def _saml_page(nodes: list[dict[str, Any]], *, has_next: bool = False, cursor: str | None = None) -> dict[str, Any]:
    return {
        "data": {
            "organization": {
                "samlIdentityProvider": {
                    "externalIdentities": {
                        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                        "nodes": nodes,
                    }
                }
            }
        }
    }


_SAML = _saml_page(
    [
        {"user": {"login": "alice"}, "samlIdentity": {"nameId": "alice@acme.test"}, "scimIdentity": None},
        {
            "user": {"login": "bob"},
            "samlIdentity": {"nameId": "urn:opaque:42"},
            "scimIdentity": {"username": "bob@acme.test"},
        },
    ]
)

_BASE = {
    **_ORG_SURFACE,
    "/graphql": _SAML,
    f"/orgs/{ORG}/members?role=admin": [{"id": 1, "login": "alice"}],
    f"/orgs/{ORG}/members?role=member": [{"id": 2, "login": "bob"}],
    f"/orgs/{ORG}/members?filter=2fa_disabled": [{"id": 1, "login": "alice"}],
    f"/orgs/{ORG}/teams/platform/members": [{"id": 2, "login": "bob"}],
    f"/orgs/{ORG}/teams/platform/repos": _REPOS,
    f"/orgs/{ORG}/teams": _TEAMS,
    f"/orgs/{ORG}/repos": _REPOS,
    f"/repos/{ORG}/web-app/collaborators": [{"id": 3, "login": "carol", "permissions": {}}],
    f"/orgs/{ORG}/outside_collaborators": [],
    f"/orgs/{ORG}/audit-log": [],
    f"/orgs/{ORG}": {"id": 42, "login": ORG},
}


def _collector(overrides: dict[str, Any] | None = None) -> tuple[GitHubCollector, _CountingTransport]:
    transport = _CountingTransport({**_BASE, **(overrides or {})})
    return GitHubCollector(GitHubClient(transport, org_login=ORG)), transport


def _drain(collector: GitHubCollector) -> dict[str, int]:
    return {object_type: len(list(collector.collect(object_type))) for object_type in collector.discover()}


def test_team_and_repo_listings_are_fetched_once_per_run() -> None:
    # team / team_membership / team_repo_permission all need the team list, and
    # repository / repo_collaborator both need the repo list.
    collector, transport = _collector()
    _drain(collector)
    assert transport.calls.count(f"/orgs/{ORG}/teams?per_page=100") == 1
    assert transport.calls.count(f"/orgs/{ORG}/repos?per_page=100") == 1


def test_a_full_run_collects_every_object_type() -> None:
    collector, _ = _collector()
    counts = _drain(collector)
    assert counts["member"] == 2
    assert counts["team"] == 1
    assert counts["team_membership"] == 1
    assert counts["repository"] == 1
    assert collector.skipped_object_types == {}


def test_a_plan_gated_audit_log_is_skipped_not_raised() -> None:
    collector, _ = _collector({f"/orgs/{ORG}/audit-log": _http_error(403)})
    counts = _drain(collector)
    assert counts["audit_log"] == 0
    assert counts["member"] == 2  # the rest of the tenant still collected
    assert collector.skipped_object_types == {"audit_log": "permission"}


def test_a_throttled_audit_log_raises_rather_than_reporting_zero_events() -> None:
    # Skipping here would look identical to "this org has no audit events".
    throttled = _http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "99999999999"})
    collector, _ = _collector({f"/orgs/{ORG}/audit-log": throttled})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("audit_log"))
    assert collector.skipped_object_types == {}


def test_a_failure_on_a_required_object_type_still_fails_the_run() -> None:
    collector, _ = _collector({f"/orgs/{ORG}/repos": _http_error(403)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("repository"))


def test_unreadable_2fa_state_degrades_members_to_unknown() -> None:
    # Listing 2FA-disabled members needs org ownership; a non-owner admin can
    # still enumerate members.
    collector, _ = _collector({f"/orgs/{ORG}/members?filter=2fa_disabled": _http_error(403)})
    members = list(collector.collect("member"))
    assert len(members) == 2
    assert {m.payload["two_factor_disabled"] for m in members} == {None}
    assert collector.skipped_object_types == {"member.two_factor": "permission"}


def test_2fa_state_is_recorded_per_member_when_readable() -> None:
    collector, _ = _collector()
    by_login = {m.payload["login"]: m.payload for m in collector.collect("member")}
    assert by_login["alice"]["two_factor_disabled"] is True
    assert by_login["bob"]["two_factor_disabled"] is False


def test_an_unknown_object_type_is_rejected() -> None:
    collector, _ = _collector()
    with pytest.raises(ValueError, match="widget"):
        list(collector.collect("widget"))


def test_the_audit_log_request_pins_include_and_order() -> None:
    """`include=web` excludes git clone/push volume, and `order=asc`
    keeps pagination stable while new entries arrive during the walk."""
    collector, transport = _collector()
    list(collector.collect("audit_log"))

    path = next(p for p in transport.calls if "audit-log" in p)
    assert "include=web" in path
    assert "order=asc" in path
    assert "phrase" not in path


def test_an_incremental_audit_collection_narrows_by_created_at() -> None:
    from datetime import UTC, datetime

    collector, transport = _collector()
    list(collector.collect("audit_log", since=datetime(2026, 8, 30, 12, 0, tzinfo=UTC)))

    path = next(p for p in transport.calls if "audit-log" in p)
    assert "phrase=created%3A%3E%3D2026-08-30T12%3A00%3A00Z" in path


def test_since_is_ignored_for_object_types_that_cannot_use_it() -> None:
    from datetime import UTC, datetime

    collector, transport = _collector()
    list(collector.collect("member", since=datetime(2026, 8, 30, tzinfo=UTC)))

    assert all("phrase" not in path for path in transport.calls)


# -- org security surface ------------------------------------------


def test_a_webhook_url_never_reaches_a_raw_object() -> None:
    """Webhook URLs routinely carry a credential in the path or query string.

    `raw_source` is persisted verbatim, so redacting in the normalizer would
    still have written the token to the database. It has to happen here.
    """
    collector, _ = _collector()

    hooks = list(collector.collect("org_webhook"))

    config = hooks[0].payload["config"]
    assert "url" not in config
    assert "tok-en" not in str(hooks[0].payload)
    assert config["url_host"] == "hooks.example.test"
    assert config["url_scheme"] == "https"
    # The masked placeholder GitHub returns is dropped too, rather than stored.
    assert "secret" not in config


def test_an_actions_variable_value_never_reaches_a_raw_object() -> None:
    # GitHub returns org variable values on this endpoint, and operators put
    # things in variables that belong in secrets.
    collector, _ = _collector()

    variables = list(collector.collect("actions_variable"))

    assert variables[0].payload["name"] == "LEGACY"
    assert "value" not in variables[0].payload
    assert "super-secret" not in str(variables[0].payload)


def test_actions_permissions_merges_both_endpoints_into_one_object() -> None:
    collector, _ = _collector()

    permissions = list(collector.collect("actions_permission"))

    assert len(permissions) == 1
    assert permissions[0].payload["allowed_actions"] == "all"
    assert permissions[0].payload["default_workflow_permissions"] == "write"


def test_every_org_surface_family_degrades_instead_of_failing() -> None:
    """A classic PAT cannot read most of this without a write-shaped scope.

    Reduced coverage has to be the outcome, not a failed sync -- otherwise the
    recommended read-only credential cannot sync the org at all.
    """
    # The org families, named explicitly rather than derived from
    # OPTIONAL_OBJECT_TYPES: per-repo posture is also optional but records
    # sub-family labels, and is covered by its own tests below.
    org_families = {
        "actions_permission",
        "runner_group",
        "self_hosted_runner",
        "actions_secret",
        "actions_variable",
        "org_webhook",
        "installed_app",
        "credential_authorization",
        "org_ruleset",
        "security_manager",
        "custom_org_role",
        "org_invitation",
        "pat_request",
        # Extended coverage
        "copilot_policy",
        "copilot_seat",
        "approved_pat",
    }

    gated = {path: _http_error(403) for path in _ORG_SURFACE}
    # IP allow list uses GraphQL -- gate it separately via GraphQL error.
    gated["/graphql"] = {"errors": [{"type": "FORBIDDEN", "message": "Not accessible"}]}
    collector, _ = _collector(gated)

    counts = _drain(collector)

    assert all(counts[object_type] == 0 for object_type in org_families)
    assert org_families <= set(collector.skipped_object_types)
    # Core inventory is untouched by the gate.
    assert counts["member"] == 2
    assert counts["repository"] == 1


def test_a_throttled_org_surface_family_still_fails_the_run() -> None:
    throttled = _http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "99999999999"})
    collector, _ = _collector({f"/orgs/{ORG}/hooks": throttled})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("org_webhook"))
    assert collector.skipped_object_types == {}


# -- risk-tiered repo posture --------------------------------------


def _repo(repo_id: int, name: str, visibility: str) -> dict[str, Any]:
    return {
        "id": repo_id,
        "name": name,
        "private": visibility != "public",
        "visibility": visibility,
        "default_branch": "main",
        "permissions": {},
    }


_TIER_REPOS = [
    _repo(9101, "internal-tool", "private"),
    _repo(9102, "billing", "private"),
    _repo(9103, "docs-site", "public"),
    _repo(9104, "shared-lib", "internal"),
    _repo(9105, "vendor-work", "private"),
]


def _tier_transport(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        **_BASE,
        f"/orgs/{ORG}/repos": _TIER_REPOS,
        f"/orgs/{ORG}/outside_collaborators": [{"id": 77, "login": "vendor"}],
    }
    for repo in _TIER_REPOS:
        name = repo["name"]
        base[f"/repos/{ORG}/{name}/collaborators"] = []
        base[f"/repos/{ORG}/{name}/branches/main/protection"] = {"enforce_admins": {"enabled": True}}
        base[f"/repos/{ORG}/{name}/rulesets"] = []
        base[f"/repos/{ORG}/{name}/hooks"] = []
        base[f"/repos/{ORG}/{name}/keys"] = []
        base[f"/repos/{ORG}/{name}/environments"] = {"environments": []}
        base[f"/repos/{ORG}/{name}/actions/permissions"] = {"enabled": True}
        base[f"/repos/{ORG}/{name}/secret-scanning/alerts"] = []
        # Extended coverage
        base[f"/repos/{ORG}/{name}/dependabot/alerts"] = []
        base[f"/repos/{ORG}/{name}/code-scanning/alerts"] = []
        base[f"/repos/{ORG}/{name}/vulnerability-alerts"] = {}
        base[f"/repos/{ORG}/{name}/code-scanning/default-setup"] = {"state": "configured"}
    base[f"/repos/{ORG}/billing/collaborators"] = [{"id": 5, "login": "erin", "permissions": {"admin": True}}]
    base[f"/repos/{ORG}/vendor-work/collaborators"] = [{"id": 77, "login": "vendor", "permissions": {"pull": True}}]
    base.update(overrides)
    return base


def _tier_collector(**kwargs: Any) -> GitHubCollector:
    return GitHubCollector(GitHubClient(_CountingTransport(_tier_transport()), org_login=ORG), **kwargs)


def _deep_scanned(collector: GitHubCollector) -> set[str]:
    return {str(repo["name"]) for repo in collector._deep_scan_repos()}


def test_the_default_tier_is_exposure_and_bypassed_access_not_everything() -> None:
    """~6 calls per repo means a thousand-repo org cannot be scanned whole.

    The tier is the repos where protection matters most: reachable beyond
    their team, or holding access that bypasses the team model.
    """
    collector = _tier_collector()

    assert _deep_scanned(collector) == {
        "docs-site",  # public
        "shared-lib",  # internal
        "billing",  # direct admin collaborator
        "vendor-work",  # outside collaborator
    }
    # A private repo with only ordinary team access is not worth six calls.
    assert "internal-tool" not in _deep_scanned(collector)


def test_an_operator_can_name_the_repositories_to_scan() -> None:
    collector = _tier_collector(deep_scan_repos=["internal-tool"])
    assert _deep_scanned(collector) == {"internal-tool"}


def test_an_operator_can_ask_for_everything() -> None:
    collector = _tier_collector(deep_scan_all=True)
    assert _deep_scanned(collector) == {r["name"] for r in _TIER_REPOS}


def test_exceeding_the_cap_is_reported_rather_than_silently_truncated() -> None:
    # Scanning a prefix and calling the run complete would report every
    # unscanned repository's posture as deleted on the next full run.
    collector = _tier_collector(deep_scan_all=True, deep_scan_limit=2)

    assert len(collector._deep_scan_repos()) == 2
    assert collector.skipped_object_types == {"repo_posture.truncated": "deep_scan_limit=2"}


def test_the_selection_is_computed_once_per_run() -> None:
    collector = _tier_collector()
    first = collector._deep_scan_repos()
    assert collector._deep_scan_repos() is first


def test_unreadable_outside_collaborators_narrow_the_tier_without_breaking_it() -> None:
    transport = _CountingTransport({**_tier_transport(), f"/orgs/{ORG}/outside_collaborators": _http_error(403)})
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    scanned = _deep_scanned(collector)

    # Visibility and direct-admin still select; only the outside-collaborator
    # signal is lost, and it is recorded rather than assumed absent.
    assert scanned == {"docs-site", "shared-lib", "billing"}
    assert "repo_posture.outside_collaborators" in collector.skipped_object_types


def test_an_unprotected_branch_is_a_finding_not_reduced_coverage() -> None:
    """GitHub 404s an unprotected branch.

    Recording that as a skip would mark every run containing an unprotected
    repository PARTIAL_FAILURE and suppress deletion detection tenant-wide.
    """
    transport = _CountingTransport(
        {**_tier_transport(), f"/repos/{ORG}/docs-site/branches/main/protection": _http_error(404)}
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    rows = {r.provider_id: r.payload for r in collector.collect("repo_branch_protection")}

    assert rows["9103"]["protected"] is False
    assert collector.skipped_object_types == {}


def test_a_forbidden_branch_protection_read_is_reduced_coverage() -> None:
    transport = _CountingTransport(
        {**_tier_transport(), f"/repos/{ORG}/docs-site/branches/main/protection": _http_error(403)}
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    list(collector.collect("repo_branch_protection"))

    assert collector.skipped_object_types == {"repo_branch_protection.get": "permission"}


def test_a_repo_webhook_url_never_reaches_a_raw_object() -> None:
    transport = _CountingTransport(
        {
            **_tier_transport(),
            f"/repos/{ORG}/docs-site/hooks": [
                {"id": 1, "active": True, "config": {"url": "https://ci.example.test/h/tok-en"}}
            ],
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    hooks = list(collector.collect("repo_webhook"))

    assert "tok-en" not in str(hooks[0].payload)
    assert hooks[0].payload["hook"]["config"]["url_host"] == "ci.example.test"


def test_only_the_count_of_secret_scanning_alerts_is_collected() -> None:
    transport = _CountingTransport(
        {
            **_tier_transport(),
            f"/repos/{ORG}/docs-site/secret-scanning/alerts": [
                {"number": 1, "secret": "ghp_a_real_looking_secret", "state": "open"},
                {"number": 2, "secret": "another", "state": "open"},
            ],
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    alerts = {r.provider_id: r.payload for r in collector.collect("secret_scanning_alert")}

    assert alerts["9103"]["open_alert_count"] == 2
    # A leaked credential is a signal; the credential is not something an
    # inventory tool should hold.
    assert "ghp_a_real_looking_secret" not in str(alerts)


def test_repo_collaborators_are_fetched_once_even_though_tiering_needs_them() -> None:
    collector = _tier_collector()
    transport = collector.client.transport

    list(collector.collect("repo_collaborator"))
    collector._deep_scan_repos()

    calls = [c for c in transport.calls if c.endswith("collaborators?affiliation=direct&per_page=100")]
    assert len(calls) == len(_TIER_REPOS)


def test_saml_identities_are_stitched_onto_members() -> None:
    collector, transport = _collector()
    by_login = {m.payload["login"]: m.payload for m in collector.collect("member")}
    assert by_login["alice"]["saml_name_id"] == "alice@acme.test"
    assert by_login["bob"]["saml_name_id"] == "urn:opaque:42"
    assert by_login["bob"]["scim_username"] == "bob@acme.test"
    assert collector.skipped_object_types == {}
    # One GraphQL walk per run, however many member listings need it.
    list(collector.collect("member"))
    assert transport.calls.count("/graphql") == 1


def test_an_org_without_saml_reports_reduced_coverage_not_failure() -> None:
    collector, _ = _collector({"/graphql": {"data": {"organization": {"samlIdentityProvider": None}}}})
    members = list(collector.collect("member"))
    assert len(members) == 2
    assert all("saml_name_id" not in m.payload for m in members)
    assert collector.skipped_object_types == {"member.saml_identity": "not_configured"}


def test_a_graphql_permission_gate_on_saml_identities_degrades_the_run() -> None:
    forbidden = {"errors": [{"type": "FORBIDDEN", "message": "Resource not accessible by integration"}]}
    collector, _ = _collector({"/graphql": forbidden})
    members = list(collector.collect("member"))
    assert len(members) == 2
    assert collector.skipped_object_types == {"member.saml_identity": "permission"}


def test_a_graphql_walk_follows_page_cursors() -> None:
    class _PagedTransport(_CountingTransport):
        def request(self, method: str, path: str, **kwargs: Any) -> Any:
            if path == "/graphql":
                self.calls.append(path)
                cursor = kwargs["json"]["variables"]["cursor"]
                if cursor is None:
                    return _saml_page(
                        [{"user": {"login": "alice"}, "samlIdentity": {"nameId": "a@x"}}], has_next=True, cursor="c1"
                    )
                return _saml_page([{"user": {"login": "bob"}, "samlIdentity": {"nameId": "b@x"}}])
            return super().request(method, path, **kwargs)

    transport = _PagedTransport(dict(_BASE))
    rows = GitHubClient(transport, org_login=ORG).list_saml_external_identities()
    assert [r["login"] for r in rows] == ["alice", "bob"]
    assert transport.calls.count("/graphql") == 2


class _EndlessGraphQLTransport(_CountingTransport):
    """Answers every GraphQL page with ``hasNextPage`` and the given cursor."""

    def __init__(self, responses: dict[str, Any], page: Any) -> None:
        super().__init__(responses)
        self.page = page

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        if path == "/graphql":
            self.calls.append(path)
            cursor = kwargs["json"]["variables"]["cursor"]
            return self.page(cursor)
        return super().request(method, path, **kwargs)


def _saml_next(cursor: str | None) -> dict[str, Any]:
    return _saml_page([{"user": {"login": f"u{cursor}"}}], has_next=True, cursor=f"{cursor or 0}x")


def _ip_next(cursor: str | None) -> dict[str, Any]:
    page = _ip_allow_list_response("ENABLED", [{"id": f"E{cursor}"}])
    page["data"]["organization"]["ipAllowListEntries"]["pageInfo"] = {"hasNextPage": True, "endCursor": f"{cursor}x"}
    return page


@pytest.mark.parametrize(
    ("call", "page"),
    [
        (lambda client: client.list_saml_external_identities(), _saml_next),
        (lambda client: client.list_ip_allow_list(), _ip_next),
    ],
    ids=["saml", "ip_allow_list"],
)
def test_a_graphql_walk_past_the_page_cap_raises_instead_of_truncating(call: Any, page: Any) -> None:
    transport = _EndlessGraphQLTransport(dict(_BASE), page)

    with pytest.raises(RuntimeError, match="exceeded 100 pages"):
        call(GitHubClient(transport, org_login=ORG))
    assert transport.calls.count("/graphql") == 100


def _no_cursor_saml(cursor: str | None) -> dict[str, Any]:
    return _saml_page([{"user": {"login": "alice"}}], has_next=True, cursor=None)


def _no_cursor_ip(cursor: str | None) -> dict[str, Any]:
    page = _ip_allow_list_response("ENABLED", [{"id": "E1"}])
    page["data"]["organization"]["ipAllowListEntries"]["pageInfo"] = {"hasNextPage": True, "endCursor": None}
    return page


@pytest.mark.parametrize(
    ("call", "page"),
    [
        (lambda client: client.list_saml_external_identities(), _no_cursor_saml),
        (lambda client: client.list_ip_allow_list(), _no_cursor_ip),
    ],
    ids=["saml", "ip_allow_list"],
)
def test_a_graphql_page_claiming_more_without_a_cursor_raises(call: Any, page: Any) -> None:
    # Following a null cursor would refetch page one until the cap.
    transport = _EndlessGraphQLTransport(dict(_BASE), page)

    with pytest.raises(RuntimeError, match="endCursor is missing"):
        call(GitHubClient(transport, org_login=ORG))
    assert transport.calls.count("/graphql") == 1


# -- Extended: IP allow list, Copilot, PATs, alert counts ----------------


def _ip_allow_list_response(enabled: str = "DISABLED", entries: list | None = None) -> dict[str, Any]:
    return {
        "data": {
            "organization": {
                "ipAllowListEnabledSetting": enabled,
                "ipAllowListEntries": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": entries or [],
                },
            }
        }
    }


def test_ip_allow_list_returns_enabled_flag_and_entries() -> None:
    entry = {"id": "EI_1", "allowListValue": "203.0.113.0/24", "isActive": True, "name": "Corp office"}
    transport = _CountingTransport({**_BASE, "/graphql": _ip_allow_list_response("ENABLED", [entry])})
    client = GitHubClient(transport, org_login=ORG)

    enabled_setting, entries = client.list_ip_allow_list()

    assert enabled_setting == "ENABLED"
    assert len(entries) == 1
    assert entries[0]["allowListValue"] == "203.0.113.0/24"


def test_ip_allow_list_disabled_returns_disabled_flag() -> None:
    transport = _CountingTransport({**_BASE, "/graphql": _ip_allow_list_response("DISABLED")})
    client = GitHubClient(transport, org_login=ORG)

    enabled_setting, entries = client.list_ip_allow_list()

    assert enabled_setting == "DISABLED"
    assert entries == []


def test_ip_allow_list_graphql_permission_error_degrades_gracefully() -> None:
    forbidden = {"errors": [{"type": "FORBIDDEN", "message": "Not accessible"}]}
    collector, _ = _collector({"/graphql": forbidden})

    objects = list(collector.collect("org_ip_allow_list"))

    # Degrades instead of raising -- the SAML path had the same treatment.
    assert collector.skipped_object_types.get("org_ip_allow_list") == "permission"
    assert objects == []


def test_copilot_policy_collects_the_org_settings() -> None:
    policy_data = {
        "seat_management_setting": "assign_selected",
        "public_code_suggestions": "allow",
    }
    collector, _ = _collector({f"/orgs/{ORG}/copilot/billing": policy_data})

    objects = list(collector.collect("copilot_policy"))

    assert len(objects) == 1
    assert objects[0].payload["public_code_suggestions"] == "allow"


def test_copilot_seats_yield_one_object_per_assignee() -> None:
    seats_data = {
        "total_seats": 2,
        "seats": [
            {"assignee": {"login": "alice", "id": 1}, "last_activity_at": "2026-09-15T00:00:00Z"},
            {"assignee": {"login": "bob", "id": 2}, "last_activity_at": None},
        ],
    }
    collector, _ = _collector({f"/orgs/{ORG}/copilot/billing/seats": seats_data})

    objects = list(collector.collect("copilot_seat"))

    assert len(objects) == 2
    assert {o.provider_id for o in objects} == {"alice", "bob"}


def test_a_copilot_seat_without_a_login_is_skipped() -> None:
    seats_data = {"total_seats": 1, "seats": [{"assignee": {}, "last_activity_at": None}]}
    collector, _ = _collector({f"/orgs/{ORG}/copilot/billing/seats": seats_data})

    objects = list(collector.collect("copilot_seat"))

    assert objects == []


def test_approved_pats_yield_one_object_per_token() -> None:
    pat = {"id": 7801, "owner": {"login": "carol"}, "repository_selection": "all", "permissions": {}}
    collector, _ = _collector({f"/orgs/{ORG}/personal-access-tokens": [pat]})

    objects = list(collector.collect("approved_pat"))

    assert len(objects) == 1
    assert objects[0].provider_id == "7801"


def test_dependabot_alert_count_follows_secret_scanning_pattern() -> None:
    alerts = [{"number": 1, "state": "open"}, {"number": 2, "state": "open"}]
    transport = _CountingTransport(
        {
            **_tier_transport(),
            f"/repos/{ORG}/docs-site/dependabot/alerts": alerts,
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    results = {r.provider_id: r.payload for r in collector.collect("dependabot_alert")}

    assert results["9103"]["open_alert_count"] == 2


def test_code_scanning_alert_count_is_zero_when_no_alerts() -> None:
    transport = _CountingTransport({**_tier_transport()})
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    results = {r.provider_id: r.payload for r in collector.collect("code_scanning_alert")}

    assert all(r["open_alert_count"] == 0 for r in results.values())


def test_repo_vulnerability_alerts_enabled_is_true_when_204() -> None:
    """204 from the vulnerability-alerts probe means alerts are enabled."""
    transport = _CountingTransport(
        {
            **_tier_transport(),
            # The transport answers None for GitHub's empty 204 body.
            f"/repos/{ORG}/docs-site/vulnerability-alerts": None,
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    results = {r.provider_id: r.payload for r in collector.collect("repo_vulnerability_alerts")}

    assert results["9103"]["enabled"] is True


def test_repo_vulnerability_alerts_disabled_is_false_when_404() -> None:
    """404 means vulnerability alerts are not enabled -- that is the finding."""
    transport = _CountingTransport(
        {
            **_tier_transport(),
            f"/repos/{ORG}/docs-site/vulnerability-alerts": _http_error(404),
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    results = {r.provider_id: r.payload for r in collector.collect("repo_vulnerability_alerts")}

    assert results["9103"]["enabled"] is False
    # 404 is a finding, not reduced coverage
    assert "repo_vulnerability_alerts.get" not in collector.skipped_object_types


def test_repo_code_scanning_setup_is_collected() -> None:
    setup = {"state": "configured", "languages": ["python"], "query_suite": "default"}
    transport = _CountingTransport(
        {
            **_tier_transport(),
            f"/repos/{ORG}/docs-site/code-scanning/default-setup": setup,
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    results = {r.provider_id: r.payload for r in collector.collect("repo_code_scanning")}

    assert results["9103"]["state"] == "configured"
    assert results["9103"]["languages"] == ["python"]


def test_repo_code_scanning_setup_not_available_is_not_configured() -> None:
    """404 from the code-scanning setup endpoint means GHAS is not available."""
    transport = _CountingTransport(
        {
            **_tier_transport(),
            f"/repos/{ORG}/docs-site/code-scanning/default-setup": _http_error(404),
        }
    )
    collector = GitHubCollector(GitHubClient(transport, org_login=ORG))

    results = {r.provider_id: r.payload for r in collector.collect("repo_code_scanning")}

    assert results["9103"]["state"] == "not-configured"
