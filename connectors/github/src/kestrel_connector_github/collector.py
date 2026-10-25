# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Translates GitHubClient responses into RawObjects, one per manifest
object_type. Cross-cutting per-member annotations (org role, 2FA status) are
computed here so the normalizer can stay a pure, single-object mapping
function with no need to cross-reference other API calls.

Two behaviours are load-bearing:

* **Team and repo listings are memoized per collector instance.** Four object
  types need the same two listings; without the cache a sync walked every team
  twice and every repo twice, doubling the request cost of the most expensive
  calls in the run.
* **Plan- and permission-gated families degrade instead of failing.** The audit
  log is GitHub Enterprise Cloud only and the 2FA filter needs org ownership,
  so a 403 on either must not discard the members, teams, repos, and grants
  that already collected successfully. Skips are recorded on
  ``skipped_object_types`` and read back by the sync pipeline, which downgrades
  the run to PARTIAL_FAILURE and suppresses deletion detection — an incomplete
  inventory must never be read as "everything disappeared".
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.base import HealthCheckResult, RawObject
from kestrel.connectors.sdk.payload import reduce_url_to_host

from kestrel_connector_github.client import GitHubClient
from kestrel_connector_github.health import check_health
from kestrel_connector_github.http import classify_github_failure, http_status, is_skippable

OBJECT_TYPES = [
    "organization",
    "member",
    "team",
    "team_membership",
    "team_repo_permission",
    "repository",
    "repo_collaborator",
    "outside_collaborator",
    "audit_log",
    # -- org security surface ------------------------------------
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
    # -- IP allow list (GraphQL) ---------------------------------
    "org_ip_allow_list",
    # -- Copilot -------------------------------------------------
    "copilot_policy",
    "copilot_seat",
    # -- approved fine-grained PATs ------------------------------
    "approved_pat",
    # -- org packages --------------------------------------------
    "org_package",
    # -- per-repository posture ----------------------------------
    "repo_security_analysis",
    "repo_branch_protection",
    "repo_ruleset",
    "repo_webhook",
    "deploy_key",
    "repo_environment",
    "repo_actions_permission",
    "secret_scanning_alert",
    # -- additional per-repo alert counts (extended) ------------
    "dependabot_alert",
    "code_scanning_alert",
    # -- additional per-repo posture (extended) -----------------
    "repo_vulnerability_alerts",
    "repo_code_scanning",
]

# Deep repo posture is roughly six calls per repository. Running it across a
# thousand-repo org would consume a classic PAT's entire hourly budget before
# the sync finished, so it runs against a risk-tiered selection instead
# (`_deep_scan_repos`). The cap is the backstop for an org where even the
# selection is large.
DEFAULT_DEEP_SCAN_LIMIT = 200

# Object types whose absence degrades the run rather than failing it. Everything
# else is core inventory: a 403 there means the credential is wrong, and the
# health check's scope message is the right way to surface that.
#
# The entire org security surface is optional. Each family needs a permission a
# classic PAT grants only through a write-shaped scope (`admin:org`,
# `admin:org_hook`) that read-only scope enforcement rejects, so a PAT tenant
# reads few of them and a GitHub App tenant reads most. That is the difference
# the setup doc calls "degraded" versus "full" coverage, and it must show as
# reduced coverage rather than a failed sync.
OPTIONAL_OBJECT_TYPES = frozenset(
    {
        "audit_log",
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
        "org_ip_allow_list",
        "copilot_policy",
        "copilot_seat",
        "approved_pat",
        "org_package",
        "repo_security_analysis",
        "repo_branch_protection",
        "repo_ruleset",
        "repo_webhook",
        "deploy_key",
        "repo_environment",
        "repo_actions_permission",
        "secret_scanning_alert",
        "dependabot_alert",
        "code_scanning_alert",
        "repo_vulnerability_alerts",
        "repo_code_scanning",
    }
)


def _is_risky_collaborator(row: dict, outside_logins: set[str]) -> bool:
    """Whether one direct collaborator makes a private repo worth deep-scanning.

    Two shapes of access bypass the team model: an admin grant handed to a
    person directly, and anyone from outside the organization.
    """
    if str(row.get("login") or "") in outside_logins:
        return True
    if (row.get("permissions") or {}).get("admin"):
        return True
    return str(row.get("role_name") or "").lower() == "admin"


def _repo_visibility(repo: dict) -> str:
    """Repository visibility, from whichever field the payload carries.

    Duplicated deliberately rather than imported from the normalizer: the
    collector decides *what to fetch* and must not depend on the module that
    decides what things mean.
    """
    if repo.get("visibility") == "internal":
        return "internal"
    return "public" if not repo.get("private", True) else "private"


def _redact_webhook(hook: dict) -> dict:
    """A webhook payload with the destination URL reduced to its host.

    Applied at collection so the full URL never reaches `raw_source`, which is
    persisted verbatim.
    """
    redacted = dict(hook)
    config = reduce_url_to_host(hook.get("config") or {}, "url")
    # `secret` is returned as a masked placeholder, but drop it regardless.
    config.pop("secret", None)
    redacted["config"] = config
    return redacted


class GitHubCollector:
    def __init__(
        self,
        client: GitHubClient,
        *,
        deep_scan_repos: list[str] | None = None,
        deep_scan_all: bool = False,
        deep_scan_limit: int = DEFAULT_DEEP_SCAN_LIMIT,
    ) -> None:
        self.client = client
        # object_type / sub-family -> failure class, read by the sync pipeline.
        self.skipped_object_types: dict[str, str] = {}
        self._teams: list[dict] | None = None
        self._repos: list[dict] | None = None
        self._collaborators: dict[str, list[dict]] | None = None
        self._deep_scan: list[dict] | None = None
        self._saml_by_login: dict[str, dict] | None = None
        # Operator overrides, from ConnectorInstance.config.
        self._deep_scan_names = {name.strip() for name in (deep_scan_repos or []) if name.strip()}
        self._deep_scan_all = bool(deep_scan_all)
        self._deep_scan_limit = max(0, int(deep_scan_limit))

    # -- memoized listings -------------------------------------------------

    def _cached_teams(self) -> list[dict]:
        if self._teams is None:
            self._teams = self.client.list_teams()
        return self._teams

    def _cached_repos(self) -> list[dict]:
        if self._repos is None:
            self._repos = self.client.list_repos()
        return self._repos

    def _cached_collaborators(self) -> dict[str, list[dict]]:
        """Direct collaborators per repo name.

        `repo_collaborator` already walks every repository, so the risk tiering
        below reuses that result rather than paying for it twice.
        """
        if self._collaborators is None:
            self._collaborators = {
                str(repo["name"]): list(self.client.list_repo_collaborators(str(repo["name"])))
                for repo in self._cached_repos()
            }
        return self._collaborators

    def _deep_scan_repos(self) -> list[dict]:
        """Repositories that get per-repo posture collection.

        Deep posture is ~6 calls per repository. Against a thousand-repo org
        that is the whole hourly budget of a classic PAT, so the default is a
        risk tier rather than everything:

        * **public and internal** repositories -- reachable beyond the team
          that owns them, so their protection settings matter most;
        * repositories with an **outside collaborator**, or with a **direct
          admin** grant -- access that bypasses the team model.

        An operator can override with `deep_scan_repos` (an explicit list) or
        `deep_scan_all`. Whatever the selection, `deep_scan_limit` caps it, and
        exceeding the cap is recorded as reduced coverage rather than quietly
        scanning a prefix.
        """
        if self._deep_scan is not None:
            return self._deep_scan

        repos = self._cached_repos()
        if self._deep_scan_all:
            selected = list(repos)
        elif self._deep_scan_names:
            selected = [r for r in repos if str(r.get("name")) in self._deep_scan_names]
        else:
            collaborators = self._cached_collaborators()
            outside_logins = {
                str(row.get("login")) for row in (self._safe_outside_collaborators() or []) if row.get("login")
            }
            selected = []
            for repo in repos:
                if _repo_visibility(repo) in {"public", "internal"}:
                    selected.append(repo)
                    continue
                rows = collaborators.get(str(repo.get("name"))) or []
                if any(_is_risky_collaborator(row, outside_logins) for row in rows):
                    selected.append(repo)

        if self._deep_scan_limit and len(selected) > self._deep_scan_limit:
            self.skipped_object_types["repo_posture.truncated"] = f"deep_scan_limit={self._deep_scan_limit}"
            selected = selected[: self._deep_scan_limit]

        self._deep_scan = selected
        return self._deep_scan

    def _saml_identities_by_login(self) -> dict[str, dict]:
        """SAML/SCIM identity per member login, or empty when unreadable.

        Empty is also the honest answer for an org without SAML SSO: GitHub
        returns a null ``samlIdentityProvider`` there, and that is recorded as
        reduced coverage so an operator can tell "no email because no SSO"
        apart from "no email because the token cannot read it".
        """
        if self._saml_by_login is not None:
            return self._saml_by_login
        try:
            rows = self.client.list_saml_external_identities()
        except Exception as exc:
            if not is_skippable(exc):
                raise
            self.skipped_object_types.setdefault("member.saml_identity", classify_github_failure(exc))
            rows = []
        if not rows:
            self.skipped_object_types.setdefault("member.saml_identity", "not_configured")
        self._saml_by_login = {row["login"]: row for row in rows}
        return self._saml_by_login

    def _safe_outside_collaborators(self) -> list[dict] | None:
        """Org outside collaborators, or None when the credential cannot read them.

        Risk tiering degrades rather than failing: without this list the
        selection falls back to visibility and direct-admin grants, which is a
        smaller tier, not a broken one.
        """
        try:
            return list(self.client.list_outside_collaborators())
        except Exception as exc:
            if not is_skippable(exc):
                raise
            self.skipped_object_types.setdefault("repo_posture.outside_collaborators", classify_github_failure(exc))
            return None

    def _safe_repo_call(
        self,
        family: str,
        fn: Callable[..., Any],
        repo_name: str,
        *,
        absent_status: int | None = None,
    ) -> Any:
        """One per-repo call, separating absence from inaccessibility.

        `absent_status` is a status where the API is *answering*, not refusing:
        GitHub 404s an unprotected branch, a repository with Actions disabled,
        and one without secret scanning. Those are findings, and recording them
        as reduced coverage would mark every run with an unprotected repo
        PARTIAL_FAILURE and suppress deletion detection across the tenant.

        Anything else skippable is a genuine permission or plan gate and is
        recorded. A rate limit is neither and still fails the run.
        """
        try:
            return fn(repo_name)
        except Exception as exc:
            if absent_status is not None and http_status(exc) == absent_status:
                return None
            if not is_skippable(exc):
                raise
            self.skipped_object_types.setdefault(family, classify_github_failure(exc))
            return None

    def discover(self) -> list[str]:
        return list(OBJECT_TYPES)

    def health_check(self) -> HealthCheckResult:
        return check_health(self.client)

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        method = getattr(self, f"_collect_{object_type}", None)
        if method is None:
            raise ValueError(f"GitHubCollector does not support object_type '{object_type}'")
        try:
            if object_type == "audit_log":
                yield from self._collect_audit_log(datetime.now(UTC), since=since)
                return
            yield from method(datetime.now(UTC))
        except Exception as exc:
            if object_type in OPTIONAL_OBJECT_TYPES and is_skippable(exc):
                self.skipped_object_types[object_type] = classify_github_failure(exc)
                return
            raise

    def _collect_organization(self, now: datetime) -> Iterable[RawObject]:
        org = self.client.get_organization()
        yield RawObject(object_type="organization", provider_id=str(org["id"]), payload=org, collected_at=now)

    def _collect_member(self, now: datetime) -> Iterable[RawObject]:
        admins = {m["login"]: m for m in self.client.list_members(role="admin")}
        members = {m["login"]: m for m in self.client.list_members(role="member")}

        # Listing 2FA-disabled members requires org ownership. A non-owner org
        # admin can enumerate members but not their 2FA state, so degrade to
        # "unknown" (None) rather than silently claiming everyone is enrolled.
        # `mfa_enabled` is a nullable tri-state precisely for this case.
        no_mfa_logins: set[str] | None
        try:
            no_mfa_logins = {m["login"] for m in self.client.list_members_2fa_disabled()}
        except Exception as exc:
            if not is_skippable(exc):
                raise
            no_mfa_logins = None
            self.skipped_object_types["member.two_factor"] = classify_github_failure(exc)

        saml = self._saml_identities_by_login()
        for login, payload in {**members, **admins}.items():
            enriched = dict(payload)
            enriched["org_role"] = "admin" if login in admins else "member"
            enriched["two_factor_disabled"] = None if no_mfa_logins is None else login in no_mfa_logins
            linked = saml.get(login)
            if linked:
                enriched["saml_name_id"] = linked.get("saml_name_id")
                enriched["scim_username"] = linked.get("scim_username")
            yield RawObject(object_type="member", provider_id=str(enriched["id"]), payload=enriched, collected_at=now)

    def _collect_team(self, now: datetime) -> Iterable[RawObject]:
        for team in self._cached_teams():
            yield RawObject(object_type="team", provider_id=str(team["id"]), payload=team, collected_at=now)

    def _collect_team_membership(self, now: datetime) -> Iterable[RawObject]:
        for team in self._cached_teams():
            for member in self.client.list_team_members(team["slug"]):
                payload = {"team_slug": team["slug"], "team_id": team["id"], "member": member}
                yield RawObject(
                    object_type="team_membership",
                    provider_id=f"{team['id']}:{member['id']}",
                    payload=payload,
                    collected_at=now,
                )

    def _collect_team_repo_permission(self, now: datetime) -> Iterable[RawObject]:
        for team in self._cached_teams():
            for repo in self.client.list_team_repos(team["slug"]):
                payload = {"team_slug": team["slug"], "team_id": team["id"], "repo": repo}
                yield RawObject(
                    object_type="team_repo_permission",
                    provider_id=f"{team['id']}:{repo['id']}",
                    payload=payload,
                    collected_at=now,
                )

    def _collect_repository(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._cached_repos():
            yield RawObject(object_type="repository", provider_id=str(repo["id"]), payload=repo, collected_at=now)

    def _collect_repo_collaborator(self, now: datetime) -> Iterable[RawObject]:
        collaborators = self._cached_collaborators()
        for repo in self._cached_repos():
            for collaborator in collaborators.get(str(repo["name"])) or []:
                payload = {"repo": repo, "collaborator": collaborator}
                yield RawObject(
                    object_type="repo_collaborator",
                    provider_id=f"{repo['id']}:{collaborator['id']}",
                    payload=payload,
                    collected_at=now,
                )

    def _collect_outside_collaborator(self, now: datetime) -> Iterable[RawObject]:
        for collaborator in self.client.list_outside_collaborators():
            yield RawObject(
                object_type="outside_collaborator",
                provider_id=str(collaborator["id"]),
                payload=collaborator,
                collected_at=now,
            )

    def _collect_audit_log(self, now: datetime, *, since: datetime | None = None) -> Iterable[RawObject]:
        """`since` narrows the request to entries after the cursor watermark.

        Without it every sync re-read GitHub's default window.
        """
        for entry in self.client.list_audit_log(since=since):
            provider_id = str(entry.get("_document_id") or entry.get("id") or "")
            if not provider_id:
                continue
            yield RawObject(
                object_type="audit_log",
                provider_id=provider_id,
                payload=entry,
                collected_at=now,
            )

    # -- org security surface -------------------------------------

    def _collect_actions_permission(self, now: datetime) -> Iterable[RawObject]:
        """Org Actions policy plus the default workflow token scope.

        Two endpoints, one object type: they describe the same control surface
        and a policy asking "can any workflow write to any repo" needs both.
        """
        payload = dict(self.client.get_actions_permissions())
        payload.update(self.client.get_default_workflow_permissions())
        yield RawObject(
            object_type="actions_permission",
            provider_id="actions-permissions",
            payload=payload,
            collected_at=now,
        )

    def _collect_runner_group(self, now: datetime) -> Iterable[RawObject]:
        for group in self.client.list_runner_groups():
            group_id = str(group.get("id") or "")
            if not group_id:
                continue
            yield RawObject(
                object_type="runner_group",
                provider_id=group_id,
                payload=group,
                collected_at=now,
            )

    def _collect_self_hosted_runner(self, now: datetime) -> Iterable[RawObject]:
        for runner in self.client.list_self_hosted_runners():
            runner_id = str(runner.get("id") or "")
            if not runner_id:
                continue
            yield RawObject(
                object_type="self_hosted_runner",
                provider_id=runner_id,
                payload=runner,
                collected_at=now,
            )

    def _collect_actions_secret(self, now: datetime) -> Iterable[RawObject]:
        for secret in self.client.list_actions_secrets():
            name = str(secret.get("name") or "")
            if not name:
                continue
            yield RawObject(
                object_type="actions_secret",
                provider_id=name,
                payload=secret,
                collected_at=now,
            )

    def _collect_actions_variable(self, now: datetime) -> Iterable[RawObject]:
        """Variable names and metadata, never values.

        Unlike secrets, GitHub returns org variable *values* on this endpoint,
        and operators put things in variables that belong in secrets. The value
        is dropped here rather than in the normalizer so it never reaches a
        RawObject -- `raw_source` is persisted verbatim, so redacting later
        would still have written it to the database.
        """
        for variable in self.client.list_actions_variables():
            name = str(variable.get("name") or "")
            if not name:
                continue
            redacted = {key: value for key, value in variable.items() if key != "value"}
            yield RawObject(
                object_type="actions_variable",
                provider_id=name,
                payload=redacted,
                collected_at=now,
            )

    def _collect_org_webhook(self, now: datetime) -> Iterable[RawObject]:
        """Org webhooks, with the destination URL reduced to its host.

        Webhook URLs routinely carry a credential in the path or query string
        (a Slack incoming-webhook token, a CI trigger key). Kestrel is an
        inventory tool, not a place to accumulate other systems' secrets, so
        the full URL never reaches a RawObject. The host is what posture
        actually needs: is this delivering outside our own infrastructure.
        """
        for hook in self.client.list_org_webhooks():
            hook_id = str(hook.get("id") or "")
            if not hook_id:
                continue
            yield RawObject(
                object_type="org_webhook",
                provider_id=hook_id,
                payload=_redact_webhook(hook),
                collected_at=now,
            )

    def _collect_installed_app(self, now: datetime) -> Iterable[RawObject]:
        for installation in self.client.list_installations():
            installation_id = str(installation.get("id") or "")
            if not installation_id:
                continue
            yield RawObject(
                object_type="installed_app",
                provider_id=installation_id,
                payload=installation,
                collected_at=now,
            )

    def _collect_credential_authorization(self, now: datetime) -> Iterable[RawObject]:
        for credential in self.client.list_credential_authorizations():
            credential_id = str(credential.get("credential_id") or "")
            if not credential_id:
                continue
            yield RawObject(
                object_type="credential_authorization",
                provider_id=credential_id,
                payload=credential,
                collected_at=now,
            )

    def _collect_org_ruleset(self, now: datetime) -> Iterable[RawObject]:
        for ruleset in self.client.list_rulesets():
            ruleset_id = str(ruleset.get("id") or "")
            if not ruleset_id:
                continue
            yield RawObject(
                object_type="org_ruleset",
                provider_id=ruleset_id,
                payload=ruleset,
                collected_at=now,
            )

    def _collect_security_manager(self, now: datetime) -> Iterable[RawObject]:
        for team in self.client.list_security_managers():
            team_id = str(team.get("id") or team.get("slug") or "")
            if not team_id:
                continue
            yield RawObject(
                object_type="security_manager",
                provider_id=team_id,
                payload=team,
                collected_at=now,
            )

    def _collect_custom_org_role(self, now: datetime) -> Iterable[RawObject]:
        for role in self.client.list_custom_org_roles():
            role_id = str(role.get("id") or "")
            if not role_id:
                continue
            yield RawObject(
                object_type="custom_org_role",
                provider_id=role_id,
                payload=role,
                collected_at=now,
            )

    def _collect_org_invitation(self, now: datetime) -> Iterable[RawObject]:
        for invitation in self.client.list_pending_invitations():
            invitation_id = str(invitation.get("id") or "")
            if not invitation_id:
                continue
            yield RawObject(
                object_type="org_invitation",
                provider_id=invitation_id,
                payload=invitation,
                collected_at=now,
            )

    def _collect_pat_request(self, now: datetime) -> Iterable[RawObject]:
        for request in self.client.list_pat_requests():
            request_id = str(request.get("id") or "")
            if not request_id:
                continue
            yield RawObject(
                object_type="pat_request",
                provider_id=request_id,
                payload=request,
                collected_at=now,
            )

    # -- per-repository posture -----------------------------------
    #
    # Every payload below carries its repo so the normalizer can scope the
    # setting to that repository (subject-scoped settings) instead of
    # burying the repo name in a setting key.

    def _repo_payload(self, repo: dict) -> dict:
        return {"id": repo.get("id"), "name": repo.get("name"), "full_name": repo.get("full_name")}

    def _collect_repo_security_analysis(self, now: datetime) -> Iterable[RawObject]:
        """GHAS, secret scanning, push protection, and Dependabot enablement.

        Read from the repository payload the list call already returned, so this
        costs nothing extra and covers *every* repository rather than only the
        deep-scan tier. The block is absent for credentials that cannot see it,
        in which case there is nothing to report rather than something to guess.
        """
        for repo in self._cached_repos():
            analysis = repo.get("security_and_analysis")
            if not isinstance(analysis, dict):
                continue
            yield RawObject(
                object_type="repo_security_analysis",
                provider_id=str(repo["id"]),
                payload={"repo": self._repo_payload(repo), "security_and_analysis": analysis},
                collected_at=now,
            )

    def _collect_repo_branch_protection(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._deep_scan_repos():
            branch = str(repo.get("default_branch") or "main")
            protection = self._safe_repo_call(
                "repo_branch_protection.get",
                lambda name, b=branch: self.client.get_branch_protection(name, b),
                str(repo["name"]),
                # 404 means the branch is unprotected, which is the finding.
                absent_status=404,
            )
            yield RawObject(
                object_type="repo_branch_protection",
                provider_id=str(repo["id"]),
                payload={
                    "repo": self._repo_payload(repo),
                    "branch": branch,
                    # A 404 means the branch is genuinely unprotected. That is
                    # the finding, so it is recorded as `protected: false`
                    # rather than dropped for lack of a payload.
                    "protected": isinstance(protection, dict),
                    "protection": protection if isinstance(protection, dict) else {},
                },
                collected_at=now,
            )

    def _collect_repo_ruleset(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._deep_scan_repos():
            rulesets = self._safe_repo_call("repo_ruleset.list", self.client.list_repo_rulesets, str(repo["name"]))
            for ruleset in rulesets or []:
                yield RawObject(
                    object_type="repo_ruleset",
                    provider_id=f"{repo['id']}:{ruleset.get('id')}",
                    payload={"repo": self._repo_payload(repo), "ruleset": ruleset},
                    collected_at=now,
                )

    def _collect_repo_webhook(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._deep_scan_repos():
            hooks = self._safe_repo_call("repo_webhook.list", self.client.list_repo_webhooks, str(repo["name"]))
            for hook in hooks or []:
                yield RawObject(
                    object_type="repo_webhook",
                    provider_id=f"{repo['id']}:{hook.get('id')}",
                    # Same URL redaction as org webhooks: the destination
                    # routinely carries a credential.
                    payload={"repo": self._repo_payload(repo), "hook": _redact_webhook(hook)},
                    collected_at=now,
                )

    def _collect_deploy_key(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._deep_scan_repos():
            keys = self._safe_repo_call("deploy_key.list", self.client.list_deploy_keys, str(repo["name"]))
            for key in keys or []:
                yield RawObject(
                    object_type="deploy_key",
                    provider_id=f"{repo['id']}:{key.get('id')}",
                    payload={"repo": self._repo_payload(repo), "key": key},
                    collected_at=now,
                )

    def _collect_repo_environment(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._deep_scan_repos():
            environments = self._safe_repo_call(
                "repo_environment.list",
                self.client.list_repo_environments,
                str(repo["name"]),
                absent_status=404,
            )
            for environment in environments or []:
                yield RawObject(
                    object_type="repo_environment",
                    provider_id=f"{repo['id']}:{environment.get('id') or environment.get('name')}",
                    payload={"repo": self._repo_payload(repo), "environment": environment},
                    collected_at=now,
                )

    def _collect_repo_actions_permission(self, now: datetime) -> Iterable[RawObject]:
        for repo in self._deep_scan_repos():
            permissions = self._safe_repo_call(
                "repo_actions_permission.get",
                self.client.get_repo_actions_permissions,
                str(repo["name"]),
                # 404 means Actions is unavailable on this repository.
                absent_status=404,
            )
            if not isinstance(permissions, dict):
                continue
            yield RawObject(
                object_type="repo_actions_permission",
                provider_id=str(repo["id"]),
                payload={"repo": self._repo_payload(repo), "permissions": permissions},
                collected_at=now,
            )

    def _collect_secret_scanning_alert(self, now: datetime) -> Iterable[RawObject]:
        """Open alert *counts* only -- never a leaked credential's value."""
        for repo in self._deep_scan_repos():
            count = self._safe_repo_call(
                "secret_scanning_alert.count",
                self.client.count_open_secret_scanning_alerts,
                str(repo["name"]),
                # 404 means secret scanning is not enabled here;
                # `repo_security_analysis` already reports that.
                absent_status=404,
            )
            if count is None:
                continue
            yield RawObject(
                object_type="secret_scanning_alert",
                provider_id=str(repo["id"]),
                payload={"repo": self._repo_payload(repo), "open_alert_count": int(count)},
                collected_at=now,
            )

    # -- Extended: IP allow list, Copilot, PATs, packages, alerts --------

    def _collect_org_ip_allow_list(self, now: datetime) -> Iterable[RawObject]:
        """IP allow list configuration for the org, via GraphQL.

        GitHub returns one page of up to 100 entries per request. The enabled
        flag and the full entry list are bundled into one setting object so that
        a policy can check "enabled AND at least one active entry" without
        cross-referencing two settings.
        """
        enabled_setting, entries = self.client.list_ip_allow_list()
        yield RawObject(
            object_type="org_ip_allow_list",
            provider_id="ip-allow-list",
            payload={"enabled_setting": enabled_setting, "entries": entries},
            collected_at=now,
        )

    def _collect_copilot_policy(self, now: datetime) -> Iterable[RawObject]:
        """Org-level Copilot policy: seat management and content filtering."""
        policy = self.client.get_copilot_billing()
        yield RawObject(
            object_type="copilot_policy",
            provider_id="copilot-policy",
            payload=policy,
            collected_at=now,
        )

    def _collect_copilot_seat(self, now: datetime) -> Iterable[RawObject]:
        """One RawObject per Copilot seat assignment.

        Includes last-activity timestamp and editor, which is what the
        "inactive seat" policy needs to determine whether the seat is earning
        its cost and whether the user is still active.
        """
        for seat in self.client.list_copilot_seats():
            assignee = seat.get("assignee") or {}
            assignee_login = str(assignee.get("login") or assignee.get("id") or "")
            if not assignee_login:
                continue
            yield RawObject(
                object_type="copilot_seat",
                provider_id=assignee_login,
                payload=seat,
                collected_at=now,
            )

    def _collect_approved_pat(self, now: datetime) -> Iterable[RawObject]:
        """Approved fine-grained PATs, one object per token.

        These have been granted org access; their permission sets and repository
        selection scope are the posture signal. Token values are never returned
        by the API.
        """
        for pat in self.client.list_approved_pats():
            pat_id = str(pat.get("id") or "")
            if not pat_id:
                continue
            yield RawObject(
                object_type="approved_pat",
                provider_id=pat_id,
                payload=pat,
                collected_at=now,
            )

    # Common package types to enumerate. GitHub requires a type parameter;
    # there is no "all types" endpoint. Less common types (rubygems, nuget,
    # swift) are skipped here since most orgs do not publish them through
    # GitHub Packages; an operator can extend this list via config in future.
    _PACKAGE_TYPES = ("container", "npm", "maven", "docker")

    def _collect_org_package(self, now: datetime) -> Iterable[RawObject]:
        """Org packages across common types, one object per package.

        GitHub requires a package_type parameter. Each type is fetched
        separately. Packages not matching a collected type are not reported --
        a future config option could extend the list.
        """
        seen: set[str] = set()
        for pkg_type in self._PACKAGE_TYPES:
            try:
                packages = list(self.client.list_org_packages(pkg_type))
            except Exception as exc:
                if is_skippable(exc):
                    self.skipped_object_types.setdefault(f"org_package.{pkg_type}", classify_github_failure(exc))
                    continue
                raise
            for pkg in packages:
                pkg_name = str(pkg.get("name") or "")
                pkg_id = str(pkg.get("id") or "")
                key = f"{pkg_type}:{pkg_name or pkg_id}"
                if key in seen:
                    continue
                seen.add(key)
                yield RawObject(
                    object_type="org_package",
                    provider_id=f"{pkg_type}:{pkg_id or pkg_name}",
                    payload={"package_type": pkg_type, **pkg},
                    collected_at=now,
                )

    # -- Extended: additional per-repo alert counts ----------------------

    def _collect_dependabot_alert(self, now: datetime) -> Iterable[RawObject]:
        """Open Dependabot alert counts per deep-scan repository.

        Counts only -- advisory details (CVE, CVSS, fixed version, affected
        package) are not stored. The count is the posture signal.
        """
        for repo in self._deep_scan_repos():
            count = self._safe_repo_call(
                "dependabot_alert.count",
                self.client.count_open_dependabot_alerts,
                str(repo["name"]),
                # 404 means Dependabot is not enabled on the repo.
                absent_status=404,
            )
            if count is None:
                continue
            yield RawObject(
                object_type="dependabot_alert",
                provider_id=str(repo["id"]),
                payload={"repo": self._repo_payload(repo), "open_alert_count": int(count)},
                collected_at=now,
            )

    def _collect_code_scanning_alert(self, now: datetime) -> Iterable[RawObject]:
        """Open code-scanning alert counts per deep-scan repository.

        Counts only -- rule identifiers, affected code lines, and alert bodies
        are not stored.
        """
        for repo in self._deep_scan_repos():
            count = self._safe_repo_call(
                "code_scanning_alert.count",
                self.client.count_open_code_scanning_alerts,
                str(repo["name"]),
                # 404 means code scanning is not configured on this repo.
                absent_status=404,
            )
            if count is None:
                continue
            yield RawObject(
                object_type="code_scanning_alert",
                provider_id=str(repo["id"]),
                payload={"repo": self._repo_payload(repo), "open_alert_count": int(count)},
                collected_at=now,
            )

    # -- Extended: additional per-repo posture ---------------------------

    def _collect_repo_vulnerability_alerts(self, now: datetime) -> Iterable[RawObject]:
        """Whether Dependabot vulnerability alerts are enabled per deep-scan repository.

        GitHub returns 204 when enabled and 404 when not. The collector treats
        404 as the finding (alerts disabled) rather than reduced coverage,
        because an unmonitored repository is more dangerous than an inaccessible
        one. 403 (permission denied) is still reduced coverage.
        """
        for repo in self._deep_scan_repos():
            repo_name = str(repo["name"])
            try:
                self.client.check_vulnerability_alerts_enabled(repo_name)
                enabled: bool | None = True
            except Exception as exc:
                if http_status(exc) == 404:
                    enabled = False
                elif is_skippable(exc):
                    self.skipped_object_types.setdefault("repo_vulnerability_alerts.get", classify_github_failure(exc))
                    continue
                else:
                    raise
            yield RawObject(
                object_type="repo_vulnerability_alerts",
                provider_id=str(repo["id"]),
                payload={"repo": self._repo_payload(repo), "enabled": enabled},
                collected_at=now,
            )

    def _collect_repo_code_scanning(self, now: datetime) -> Iterable[RawObject]:
        """Code-scanning default-setup state per deep-scan repository.

        404 means GHAS is not available on the repository (not on the plan, or
        not enabled), which is treated the same as "not configured": the security
        surface exists in theory but is not active. 403 is still reduced coverage.
        """
        for repo in self._deep_scan_repos():
            setup = self._safe_repo_call(
                "repo_code_scanning.get",
                self.client.get_repo_code_scanning_default_setup,
                str(repo["name"]),
                # 404 means GHAS not available; the finding is "not configured".
                absent_status=404,
            )
            state = setup.get("state") if isinstance(setup, dict) else None
            # None here means 404 (GHAS unavailable) → treat as "not-configured".
            effective_state = state or "not-configured"
            yield RawObject(
                object_type="repo_code_scanning",
                provider_id=str(repo["id"]),
                payload={
                    "repo": self._repo_payload(repo),
                    "state": effective_state,
                    "languages": setup.get("languages") if isinstance(setup, dict) else None,
                    "query_suite": setup.get("query_suite") if isinstance(setup, dict) else None,
                },
                collected_at=now,
            )
