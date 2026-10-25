# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Health check against team.info + probe list endpoints.

Probes use ``limit=1`` so Test connection does not walk full cursor
pagination. Failures are classified as authentication, permission, network,
rate_limit, or http/unknown.

Core inventory (team / users / usergroups) must succeed for a healthy
result. Enterprise families (Admin Apps, org roles, workspaces, Audit Logs)
are optional — classified permission failures are reported but do not fail
Test connection, so a Pro/Business+ workspace can still sync members,
groups, and admin roles.
"""

from __future__ import annotations

import logging

from kestrel.connectors.sdk.base import HealthCheckResult
from kestrel.connectors.sdk.failures import FailureMessages, classify_http_failure, summarize_probe_failures

from kestrel_connector_slack.client import SlackApiError, SlackClient

_CORE_PROBES = ("team.info", "users.list", "usergroups.list")
_OPTIONAL_PROBES = (
    "admin.apps.approved.list",
    "admin.roles.listAssignments",
    "admin.teams.list",
    "audit.logs",
    # Release C — depth families.
    "admin.barriers.list",
    "admin.workflows.search",
    "admin.analytics.getFile",
)

_AUTH_ERRORS = frozenset(
    {
        "invalid_auth",
        "not_authed",
        "token_expired",
        "token_revoked",
        "account_inactive",
    }
)
_PERMISSION_ERRORS = frozenset(
    {
        "missing_scope",
        "not_allowed",
        "not_an_admin",
        "no_permission",
        "restricted_action",
        "not_allowed_token_type",
        "ekm_access_denied",
        "feature_not_enabled",
        "enterprise_is_restricted",
        "team_access_not_granted",
        "app_management_app_not_installed_on_org",
        "access_denied",
    }
)


def classify_slack_failure(exc: BaseException) -> str:
    """Map transport / Slack API failures to a coarse failure class."""
    if isinstance(exc, SlackApiError):
        err = exc.error.casefold()
        if err in _AUTH_ERRORS:
            return "authentication"
        if err in _PERMISSION_ERRORS:
            return "permission"
        if err == "ratelimited":
            return "rate_limit"
        return f"api_{exc.error}"

    klass = classify_http_failure(exc)
    # Fixture mapping misses look like permission for optional probes.
    if klass == "unknown" and "FixtureNotFound" in type(exc).__name__:
        return "permission"
    return klass


_FAILURE_MESSAGES = FailureMessages(
    authentication=(
        "Authentication failed (invalid or expired Slack token) for: {probes}. "
        "Mint a fresh org user token (Enterprise) or bot token in Slack and "
        "paste it; Kestrel does not host a Slack OAuth redirect."
    ),
    permission=(
        "Permission denied / missing scopes for: {probes}. "
        "Enterprise Grid: paste User OAuth Token (xoxp/xoxe), not Bot User "
        "OAuth Token (xoxb). Add users:read, users:read.email, "
        "usergroups:read, and team:read to User Token Scopes (not only Bot "
        "Token Scopes), then reinstall on the org and paste a fresh user "
        "token. Also needs admin.apps:read, admin.roles:read, "
        "admin.teams:read, admin.users:read, admin.conversations:read, "
        "auditlogs:read, admin.invites:read, admin.barriers:read, "
        "admin.usergroups:read, admin.workflows:read, and "
        "admin.analytics:read on User Token Scopes. "
        "conversations.connect:manage is bot-only (not a user scope). "
        "See docs/connectors/slack-setup.md."
    ),
    rate_limit=(
        "Slack rate-limited for: {probes}. "
        "Retry later; the client retries ok:false ratelimited and HTTP 429 "
        "uses Retry-After on the shared transport."
    ),
    network="Network error reaching Slack for: {probes}. Check outbound HTTPS from the worker to slack.com / api.slack.com.",
    fallback="Unreachable or missing scopes for: {probes}",
)


logger = logging.getLogger(__name__)


def check_health(client: SlackClient) -> HealthCheckResult:
    checked: dict[str, bool] = {}
    failures: dict[str, str] = {}

    for label, call in (
        ("team.info", client.get_team),
        ("users.list", client.probe_users),
        ("usergroups.list", client.probe_usergroups),
        ("admin.apps.approved.list", client.probe_approved_apps),
        ("admin.roles.listAssignments", client.probe_role_assignments),
        ("admin.teams.list", client.probe_workspaces),
        ("audit.logs", client.probe_audit_logs),
        # Release C — depth probes.
        ("admin.barriers.list", client.probe_information_barriers),
        ("admin.workflows.search", client.probe_workflows),
        ("admin.analytics.getFile", client.probe_analytics),
    ):
        try:
            call()
            checked[label] = True
        except Exception as exc:  # deliberately broad: health check classifies any failure into a status
            checked[label] = False
            failures[label] = classify_slack_failure(exc)
            logger.warning("slack health probe %s failed (%s)", label, failures[label], exc_info=True)

    core_ok = all(checked.get(label, False) for label in _CORE_PROBES)
    optional_failures = {k: v for k, v in failures.items() if k in _OPTIONAL_PROBES}
    core_failures = {k: v for k, v in failures.items() if k in _CORE_PROBES}

    if core_ok and not optional_failures:
        message = "Slack reachable with all required scopes"
    elif core_ok and optional_failures:
        extra = ", ".join(f"{k} ({v})" for k, v in sorted(optional_failures.items()))
        message = (
            "Slack reachable for members, user groups, and admin roles. "
            f"Enterprise inventory partially skipped: {extra}. "
            "Org-install an Owner user token with admin.* and auditlogs:read "
            "for full Grid posture (apps, org roles, Audit Logs)."
        )
    else:
        message = summarize_probe_failures(core_failures or failures, _FAILURE_MESSAGES)

    if core_ok and not client.enterprise_id and checked.get("admin.teams.list"):
        # admin.teams.list only answers an org-level Enterprise Grid token, so
        # this credential could read the whole org but is scoped to one
        # workspace for want of the E… id.
        message = (
            f"{message} Enterprise Grid token detected but enterprise_id is not set: "
            "Admin Apps and member inventory are limited to this workspace. "
            "Set enterprise_id (E…) for org-wide coverage."
        )

    return HealthCheckResult(
        healthy=core_ok,
        message=message,
        checked_permissions=checked,
    )
