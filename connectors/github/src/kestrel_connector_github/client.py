# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Thin typed wrapper over a Transport, translating GitHub REST v3 endpoints
into method calls. Every method builds a `path` (including any query string)
that doubles as the request signature FixtureTransport uses to find the
matching fixture file, and that LiveHTTPTransport passes straight through to
httpx.

Because the path *is* the fixture key, query-string construction has to be
deterministic: build every path through `build_path()` so parameter order is
stable and fixture mappings stay exact-match.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from kestrel.connectors.sdk.base import Transport

# GitHub's default page size is 30; 100 is the documented maximum. Every list
# endpoint below is a full walk, so the default costs ~3.3x the requests and
# burns rate limit proportionally.
PER_PAGE = 100

# GraphQL pagination for the SAML identity walk; 100 per page, so this covers
# an org of ten thousand SSO-linked members before refusing to loop forever.
_MAX_GRAPHQL_PAGES = 100

_SAML_IDENTITIES_QUERY = """
query($org: String!, $cursor: String) {
  organization(login: $org) {
    samlIdentityProvider {
      externalIdentities(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          user { login }
          samlIdentity { nameId }
          scimIdentity { username }
        }
      }
    }
  }
}
"""

# IP allow list is GraphQL-only; REST has no equivalent. The `ipAllowListEnabledSetting`
# field returns "ENABLED" or "DISABLED"; individual entries carry the CIDR/IP value,
# whether the entry is active, and an operator label.
_IP_ALLOW_LIST_QUERY = """
query($org: String!, $cursor: String) {
  organization(login: $org) {
    ipAllowListEnabledSetting
    ipAllowListEntries(first: 100, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        allowListValue
        isActive
        name
        createdAt
      }
    }
  }
}
"""

# Enterprise-level settings query. Requires an enterprise slug and a token
# scoped to the enterprise (read:enterprise for classic PATs; the enterprise
# admin App permission for GitHub Apps). Only collectible on GitHub Enterprise
# Cloud; on GHEC the enterprise owns multiple orgs so this captures settings
# that cannot be read from any single org endpoint.
_ENTERPRISE_SETTINGS_QUERY = """
query($slug: String!) {
  enterprise(slug: $slug) {
    ownerInfo {
      requiresTwoFactorAuthentication
      ipAllowListEnabledSetting
      allowActionsInOrganizations
      allowPublicRepositories
    }
    organizations(first: 100) {
      totalCount
      nodes { login databaseId }
    }
  }
}
"""


class GitHubGraphQLError(RuntimeError):
    """GraphQL answered 200 with an ``errors`` array (a permission gate, most often)."""

    def __init__(self, errors: list[Any]) -> None:
        self.errors = errors
        first = errors[0] if errors else {}
        self.error_type = str(first.get("type") or "") if isinstance(first, dict) else ""
        message = first.get("message") if isinstance(first, dict) else None
        super().__init__(f"GitHub GraphQL error: {message or errors}")


def _next_graphql_cursor(page_info: Any, what: str) -> str | None:
    """The cursor for the next page, or None when this was the last one.

    A truncated list is worse than a failed sync: deletion detection would
    tombstone everything past the cut. So a page that claims more but gives
    no cursor (refetching page one forever) raises, like the REST paginator.
    """
    page = page_info if isinstance(page_info, dict) else {}
    if not page.get("hasNextPage"):
        return None
    cursor = page.get("endCursor")
    if not cursor:
        raise RuntimeError(f"GitHub GraphQL {what}: hasNextPage is true but endCursor is missing")
    return str(cursor)


def _items(response: Any, key: str) -> list[dict[str, Any]]:
    """Rows from an endpoint that wraps its list in a named envelope.

    Several org endpoints return `{"total_count": N, "<key>": [...]}` rather
    than a bare array, and `paginate` cannot walk those -- there is one page.
    """
    if isinstance(response, list):
        return [row for row in response if isinstance(row, dict)]
    if not isinstance(response, dict):
        return []
    rows = response.get(key)
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def build_path(base: str, **params: Any) -> str:
    """Build `base?k=v&...`, dropping None values, preserving argument order."""
    pairs = [(key, value) for key, value in params.items() if value is not None]
    if not pairs:
        return base
    return f"{base}?{urlencode(pairs)}"


class GitHubClient:
    def __init__(self, transport: Transport, org_login: str, *, enterprise_slug: str | None = None) -> None:
        self.transport = transport
        self.org_login = org_login
        self.enterprise_slug = enterprise_slug

    # -- paths -------------------------------------------------------------
    # Shared by the collection calls and the health probes so that a probe
    # never needs its own fixture mapping entry.

    def _org_path(self) -> str:
        return f"/orgs/{self.org_login}"

    def _members_path(self, *, role: str | None = None, filter_: str | None = None) -> str:
        if filter_ is not None:
            return build_path(f"/orgs/{self.org_login}/members", filter=filter_, per_page=PER_PAGE)
        return build_path(f"/orgs/{self.org_login}/members", role=role, per_page=PER_PAGE)

    def _teams_path(self) -> str:
        return build_path(f"/orgs/{self.org_login}/teams", per_page=PER_PAGE)

    def _repos_path(self) -> str:
        return build_path(f"/orgs/{self.org_login}/repos", per_page=PER_PAGE)

    def _outside_collaborators_path(self) -> str:
        return build_path(f"/orgs/{self.org_login}/outside_collaborators", per_page=PER_PAGE)

    def _audit_log_path(self, *, since: datetime | None = None) -> str:
        """Audit-log path, optionally narrowed to entries after `since`.

        `include` is pinned to `web` rather than left to the default or set to
        `all`. Git events (clone, fetch, push) are the overwhelming majority of
        `all` and are operational telemetry, not posture -- collecting them
        would bury real configuration change in both the event-policy window
        and the Changes actor overlay. Pinning it also means a change to
        GitHub's default cannot silently alter what Kestrel ingests.

        `order=asc` makes pagination stable while new entries arrive during the
        walk, which a descending walk cannot guarantee.

        `since` is expressed as a `created:>=` search phrase rather than the
        opaque `after` cursor: the connector-cursor spine is
        time-based and already applies an overlap window, and audit rows dedupe
        on `provider_object_id`, so a re-read is free. The `after` token stays
        available if throughput ever needs it.
        """
        phrase = None
        if since is not None:
            stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            phrase = f"created:>={stamp}"
        return build_path(
            f"/orgs/{self.org_login}/audit-log",
            per_page=PER_PAGE,
            include="web",
            order="asc",
            phrase=phrase,
        )

    # -- collection --------------------------------------------------------

    def get_organization(self) -> dict[str, Any]:
        return self.transport.request("GET", self._org_path())

    def list_members(self, role: str) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", self._members_path(role=role)))

    def list_members_2fa_disabled(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", self._members_path(filter_="2fa_disabled")))

    def list_teams(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", self._teams_path()))

    def list_team_members(self, team_slug: str) -> list[dict[str, Any]]:
        path = build_path(f"/orgs/{self.org_login}/teams/{team_slug}/members", per_page=PER_PAGE)
        return list(self.transport.paginate("GET", path))

    def list_team_repos(self, team_slug: str) -> list[dict[str, Any]]:
        path = build_path(f"/orgs/{self.org_login}/teams/{team_slug}/repos", per_page=PER_PAGE)
        return list(self.transport.paginate("GET", path))

    def list_repos(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", self._repos_path()))

    def list_repo_collaborators(self, repo_name: str) -> list[dict[str, Any]]:
        path = build_path(
            f"/repos/{self.org_login}/{repo_name}/collaborators",
            affiliation="direct",
            per_page=PER_PAGE,
        )
        return list(self.transport.paginate("GET", path))

    def list_outside_collaborators(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", self._outside_collaborators_path()))

    def list_audit_log(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", self._audit_log_path(since=since)))

    # -- per-repository posture -----------------------------------
    #
    # These are the fan-out calls. Each one is per repository, so the collector
    # runs them only against the risk-tiered selection -- see
    # `GitHubCollector._deep_scan_repos`.

    def get_branch_protection(self, repo_name: str, branch: str) -> dict[str, Any]:
        """Protection on one branch. GitHub 404s when the branch is unprotected,
        which the collector reads as "no protection" rather than an error."""
        return self.transport.request("GET", f"/repos/{self.org_login}/{repo_name}/branches/{branch}/protection")

    def list_repo_rulesets(self, repo_name: str) -> list[dict[str, Any]]:
        return list(
            self.transport.paginate(
                "GET",
                build_path(f"/repos/{self.org_login}/{repo_name}/rulesets", per_page=PER_PAGE),
            )
        )

    def list_repo_webhooks(self, repo_name: str) -> list[dict[str, Any]]:
        return list(
            self.transport.paginate("GET", build_path(f"/repos/{self.org_login}/{repo_name}/hooks", per_page=PER_PAGE))
        )

    def list_deploy_keys(self, repo_name: str) -> list[dict[str, Any]]:
        return list(
            self.transport.paginate("GET", build_path(f"/repos/{self.org_login}/{repo_name}/keys", per_page=PER_PAGE))
        )

    def list_repo_environments(self, repo_name: str) -> list[dict[str, Any]]:
        return _items(
            self.transport.request(
                "GET",
                build_path(f"/repos/{self.org_login}/{repo_name}/environments", per_page=PER_PAGE),
            ),
            "environments",
        )

    def get_repo_actions_permissions(self, repo_name: str) -> dict[str, Any]:
        return self.transport.request("GET", f"/repos/{self.org_login}/{repo_name}/actions/permissions")

    def count_open_secret_scanning_alerts(self, repo_name: str) -> int:
        """How many secret-scanning alerts are open. Never their contents.

        A leaked credential is a posture signal; the credential itself is not
        something an inventory tool should hold, so only the count crosses this
        boundary (`docs/connectors.md`).
        """
        alerts = self.transport.paginate(
            "GET",
            build_path(
                f"/repos/{self.org_login}/{repo_name}/secret-scanning/alerts",
                state="open",
                per_page=PER_PAGE,
            ),
        )
        return sum(1 for _ in alerts)

    # -- org security surface -------------------------------------
    #
    # Every family below is permission-gated on a classic PAT and needs an
    # explicit App permission, so all of them are optional object types: a
    # credential that cannot read one degrades the run instead of failing it.
    # Reads are `GET` only; nothing here writes.

    def get_actions_permissions(self) -> dict[str, Any]:
        """Which Actions the org allows, and from where."""
        return self.transport.request("GET", f"/orgs/{self.org_login}/actions/permissions")

    def get_default_workflow_permissions(self) -> dict[str, Any]:
        """Default GITHUB_TOKEN scope handed to every workflow run.

        `write` here means any workflow in any repository starts with write
        access to the repository -- the single highest-leverage Actions setting.
        """
        return self.transport.request("GET", f"/orgs/{self.org_login}/actions/permissions/workflow")

    def list_runner_groups(self) -> list[dict[str, Any]]:
        return _items(
            self.transport.request(
                "GET",
                build_path(f"/orgs/{self.org_login}/actions/runner-groups", per_page=PER_PAGE),
            ),
            "runner_groups",
        )

    def list_self_hosted_runners(self) -> list[dict[str, Any]]:
        return _items(
            self.transport.request("GET", build_path(f"/orgs/{self.org_login}/actions/runners", per_page=PER_PAGE)),
            "runners",
        )

    def list_actions_secrets(self) -> list[dict[str, Any]]:
        """Secret *names* only. GitHub never returns org secret values."""
        return _items(
            self.transport.request("GET", build_path(f"/orgs/{self.org_login}/actions/secrets", per_page=PER_PAGE)),
            "secrets",
        )

    def list_actions_variables(self) -> list[dict[str, Any]]:
        """Variable names. Unlike secrets, GitHub *does* return values here --
        the collector drops them before they reach a RawObject."""
        return _items(
            self.transport.request("GET", build_path(f"/orgs/{self.org_login}/actions/variables", per_page=PER_PAGE)),
            "variables",
        )

    def list_org_webhooks(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", build_path(f"/orgs/{self.org_login}/hooks", per_page=PER_PAGE)))

    def list_installations(self) -> list[dict[str, Any]]:
        """GitHub Apps installed on the org, with their permission sets."""
        return _items(
            self.transport.request("GET", build_path(f"/orgs/{self.org_login}/installations", per_page=PER_PAGE)),
            "installations",
        )

    def list_saml_external_identities(self) -> list[dict[str, Any]]:
        """SAML / SCIM identities linked to org members, via GraphQL.

        REST never returns a member's email (`/orgs/{org}/members` carries only
        the login), so on an SSO-enabled org this is the only way to learn the
        address a person signs in with -- the join key cross-app correlation
        collapses on. Each row is ``{login, saml_name_id, scim_username}``.
        Walks ``pageInfo`` cursors; a fixture answers the whole set in one page.
        """
        rows: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(_MAX_GRAPHQL_PAGES):
            response = self.transport.request(
                "POST",
                "/graphql",
                json={"query": _SAML_IDENTITIES_QUERY, "variables": {"org": self.org_login, "cursor": cursor}},
            )
            errors = response.get("errors") if isinstance(response, dict) else None
            if errors:
                raise GitHubGraphQLError(errors)
            data = response.get("data") if isinstance(response, dict) else None
            org = data.get("organization") if isinstance(data, dict) else None
            provider = org.get("samlIdentityProvider") if isinstance(org, dict) else None
            if not isinstance(provider, dict):
                return []
            identities = provider.get("externalIdentities") or {}
            for node in identities.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                user = node.get("user") or {}
                saml = node.get("samlIdentity") or {}
                scim = node.get("scimIdentity") or {}
                login = user.get("login") if isinstance(user, dict) else None
                if not login:
                    continue
                rows.append(
                    {
                        "login": str(login),
                        "saml_name_id": saml.get("nameId") if isinstance(saml, dict) else None,
                        "scim_username": scim.get("username") if isinstance(scim, dict) else None,
                    }
                )
            cursor = _next_graphql_cursor(identities.get("pageInfo"), "externalIdentities")
            if cursor is None:
                return rows
        raise RuntimeError(f"GitHub GraphQL externalIdentities exceeded {_MAX_GRAPHQL_PAGES} pages")

    def list_credential_authorizations(self) -> list[dict[str, Any]]:
        """Credentials (PATs, SSH keys) authorized for SAML SSO."""
        return list(
            self.transport.paginate(
                "GET",
                build_path(f"/orgs/{self.org_login}/credential-authorizations", per_page=PER_PAGE),
            )
        )

    def list_rulesets(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", build_path(f"/orgs/{self.org_login}/rulesets", per_page=PER_PAGE)))

    def list_security_managers(self) -> list[dict[str, Any]]:
        """Teams granted the org-wide security manager role."""
        return list(self.transport.request("GET", f"/orgs/{self.org_login}/security-managers") or [])

    def list_custom_org_roles(self) -> list[dict[str, Any]]:
        return _items(
            self.transport.request("GET", build_path(f"/orgs/{self.org_login}/organization-roles", per_page=PER_PAGE)),
            "roles",
        )

    def list_pending_invitations(self) -> list[dict[str, Any]]:
        return list(self.transport.paginate("GET", build_path(f"/orgs/{self.org_login}/invitations", per_page=PER_PAGE)))

    def list_pat_requests(self) -> list[dict[str, Any]]:
        """Pending fine-grained PAT access requests awaiting an owner."""
        return list(
            self.transport.paginate(
                "GET",
                build_path(f"/orgs/{self.org_login}/personal-access-token-requests", per_page=PER_PAGE),
            )
        )

    # -- IP allow list (GraphQL-only) -------------------------------------

    def list_ip_allow_list(self) -> tuple[str | None, list[dict[str, Any]]]:
        """IP allow list enabled setting and entries for the org, via GraphQL.

        Returns ``(enabled_setting, entries)`` where ``enabled_setting`` is
        ``"ENABLED"``, ``"DISABLED"``, or None when the feature is unavailable,
        and ``entries`` is the list of configured CIDR/IP entries.
        """
        rows: list[dict[str, Any]] = []
        enabled_setting: str | None = None
        cursor: str | None = None
        for _ in range(_MAX_GRAPHQL_PAGES):
            response = self.transport.request(
                "POST",
                "/graphql",
                json={"query": _IP_ALLOW_LIST_QUERY, "variables": {"org": self.org_login, "cursor": cursor}},
            )
            errors = response.get("errors") if isinstance(response, dict) else None
            if errors:
                raise GitHubGraphQLError(errors)
            data = response.get("data") if isinstance(response, dict) else None
            org = data.get("organization") if isinstance(data, dict) else None
            if not isinstance(org, dict):
                break
            if enabled_setting is None:
                raw = org.get("ipAllowListEnabledSetting")
                enabled_setting = str(raw) if raw is not None else None
            entries_wrap = org.get("ipAllowListEntries") or {}
            for node in entries_wrap.get("nodes") or []:
                if isinstance(node, dict):
                    rows.append(node)
            cursor = _next_graphql_cursor(entries_wrap.get("pageInfo"), "ipAllowListEntries")
            if cursor is None:
                break
        else:
            raise RuntimeError(f"GitHub GraphQL ipAllowListEntries exceeded {_MAX_GRAPHQL_PAGES} pages")
        return enabled_setting, rows

    # -- Copilot ----------------------------------------------------------

    def get_copilot_billing(self) -> dict[str, Any]:
        """Org Copilot policy: seat management setting and content policy."""
        return self.transport.request("GET", f"/orgs/{self.org_login}/copilot/billing")

    def list_copilot_seats(self) -> list[dict[str, Any]]:
        """Copilot seat assignments with last-activity metadata."""
        return _items(
            self.transport.request(
                "GET",
                build_path(f"/orgs/{self.org_login}/copilot/billing/seats", per_page=PER_PAGE),
            ),
            "seats",
        )

    # -- approved fine-grained PATs ---------------------------------------

    def list_approved_pats(self) -> list[dict[str, Any]]:
        """Fine-grained PATs approved to access org resources.

        Unlike PAT *requests* (pending owner decision), these have been granted.
        The response carries owner, repository selection, and permission sets
        but never the token value.
        """
        return list(
            self.transport.paginate(
                "GET",
                build_path(f"/orgs/{self.org_login}/personal-access-tokens", per_page=PER_PAGE),
            )
        )

    # -- per-repo alert counts --------------------------------------------

    def count_open_dependabot_alerts(self, repo_name: str) -> int:
        """Count of open Dependabot vulnerability alerts. Never their contents.

        A vulnerable dependency is a posture signal; the advisory details are
        not something an inventory tool should store in bulk.
        """
        alerts = self.transport.paginate(
            "GET",
            build_path(
                f"/repos/{self.org_login}/{repo_name}/dependabot/alerts",
                state="open",
                per_page=PER_PAGE,
            ),
        )
        return sum(1 for _ in alerts)

    def count_open_code_scanning_alerts(self, repo_name: str) -> int:
        """Count of open code-scanning alerts. Never their contents."""
        alerts = self.transport.paginate(
            "GET",
            build_path(
                f"/repos/{self.org_login}/{repo_name}/code-scanning/alerts",
                state="open",
                per_page=PER_PAGE,
            ),
        )
        return sum(1 for _ in alerts)

    # -- additional per-repo posture --------------------------------------

    def check_vulnerability_alerts_enabled(self, repo_name: str) -> None:
        """Probe whether vulnerability alerts are enabled for a repository.

        GitHub returns 204 No Content when enabled, 404 when not enabled or
        when the feature is unavailable. The transport answers ``None`` for the
        empty 204 body; that is the success, not a decoding problem. The caller
        distinguishes the 404 case and raises on anything else (403 permission,
        rate limit, etc.).
        """
        self.transport.request("GET", f"/repos/{self.org_login}/{repo_name}/vulnerability-alerts")

    def get_repo_code_scanning_default_setup(self, repo_name: str) -> dict[str, Any]:
        """Code scanning default-setup configuration for a repository.

        Returns e.g. ``{"state": "configured", "languages": [...], "query_suite": "default"}``.
        GitHub 404s when GHAS is not enabled on the repo; the caller handles
        that as "feature unavailable" rather than an error.
        """
        return self.transport.request("GET", f"/repos/{self.org_login}/{repo_name}/code-scanning/default-setup")

    # -- org packages -----------------------------------------------------

    def list_org_packages(self, package_type: str) -> list[dict[str, Any]]:
        """Org packages of a specific type (container, npm, maven, etc.).

        Visibility is included in each package object. GitHub requires a
        ``package_type`` parameter; there is no endpoint that returns all types.
        """
        return list(
            self.transport.paginate(
                "GET",
                build_path(
                    f"/orgs/{self.org_login}/packages",
                    package_type=package_type,
                    per_page=PER_PAGE,
                ),
            )
        )

    # -- enterprise settings (GraphQL, requires enterprise_slug) ----------

    # -- health probes -----------------------------------------------------
    # `request` rather than `paginate`: one page is enough to prove access,
    # and Test connection must not walk a large org's full pagination.

    def probe_org(self) -> Any:
        return self.transport.request("GET", self._org_path())

    def probe_members(self) -> Any:
        return self.transport.request("GET", self._members_path(role="admin"))

    def probe_members_2fa(self) -> Any:
        return self.transport.request("GET", self._members_path(filter_="2fa_disabled"))

    def probe_teams(self) -> Any:
        return self.transport.request("GET", self._teams_path())

    def probe_repos(self) -> Any:
        return self.transport.request("GET", self._repos_path())

    def probe_audit_log(self) -> Any:
        return self.transport.request("GET", self._audit_log_path())
