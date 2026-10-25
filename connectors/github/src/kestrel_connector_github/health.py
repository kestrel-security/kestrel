# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Health check across the scopes a full GitHub sync actually needs.

Each probe maps to a required token scope (or GitHub App permission), so an
operator running Test connection learns *which* grant is missing rather than
seeing a raw httpx repr. The audit log is deliberately optional: it is a
GitHub Enterprise Cloud feature, so a Team-plan org must report healthy with
an honest caveat rather than failing outright.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from kestrel.connectors.sdk.base import HealthCheckResult
from kestrel.connectors.sdk.failures import FailureMessages, summarize_probe_failures

from kestrel_connector_github.client import GitHubClient
from kestrel_connector_github.http import classify_github_failure

# Probe label -> the scope (classic PAT) it proves. Used for the operator
# message; GitHub App installs express the same reads as permissions.
_PROBE_SCOPES = {
    "org.read": "read:org",
    "members.list": "read:org",
    "members.2fa": "read:org",
    "teams.list": "read:org",
    "repos.list": "repo",
    "audit_log.list": "read:audit_log",
}

# Not required for a useful sync — absence degrades the run, never fails it.
_OPTIONAL_PROBES = frozenset({"audit_log.list"})

# Failure classes that mean "this org/plan/token simply does not expose it",
# as opposed to a misconfiguration the operator should fix.
_OPTIONAL_SKIP_CLASSES = frozenset({"permission", "http_404"})


def _permission_message(probes: str, failures: Mapping[str, str]) -> str:
    missing = sorted({_PROBE_SCOPES[k] for k in failures if k in _PROBE_SCOPES})
    return (
        f"Permission denied for: {probes}. Missing scope(s): {', '.join(missing)}. "
        "For a classic PAT, grant read:org, read:user, and repo. Prefer a GitHub "
        "App with read-only Organization and Repository permissions."
    )


_FAILURE_MESSAGES = FailureMessages(
    authentication=(
        "Authentication failed (invalid, expired, or SSO-unauthorized credential) "
        "for: {probes}. Regenerate the token, or for SSO-protected orgs authorize "
        "it for the organization."
    ),
    permission=_permission_message,
    rate_limit="GitHub rate limit hit for: {probes}. Wait for the reset window (x-ratelimit-reset) and retry.",
    network="Network error reaching GitHub for: {probes}. Check DNS and outbound HTTPS from the worker.",
    fallback="GitHub API error for: {probes}",
)


logger = logging.getLogger(__name__)


def check_health(client: GitHubClient) -> HealthCheckResult:
    checked: dict[str, bool] = {}
    failures: dict[str, str] = {}
    org_login: str | None = None

    probes = (
        ("org.read", client.probe_org),
        ("members.list", client.probe_members),
        ("members.2fa", client.probe_members_2fa),
        ("teams.list", client.probe_teams),
        ("repos.list", client.probe_repos),
        ("audit_log.list", client.probe_audit_log),
    )

    for label, call in probes:
        try:
            result = call()
            checked[label] = True
            if label == "org.read" and isinstance(result, dict):
                login = result.get("login")
                org_login = str(login) if login else None
        except Exception as exc:  # deliberately broad: health check classifies any failure into a status
            checked[label] = False
            failures[label] = classify_github_failure(exc)
            logger.warning("github health probe %s failed (%s)", label, failures[label], exc_info=True)

    required_failures = {k: v for k, v in failures.items() if k not in _OPTIONAL_PROBES}
    healthy = not required_failures

    optional_skipped = {k: v for k, v in failures.items() if k in _OPTIONAL_PROBES and v in _OPTIONAL_SKIP_CLASSES}
    # An optional probe failing for a *non*-skippable reason (auth, rate limit,
    # network) still means something is wrong with the credential itself.
    optional_hard = {k: v for k, v in failures.items() if k in _OPTIONAL_PROBES and v not in _OPTIONAL_SKIP_CLASSES}
    if optional_hard:
        healthy = False
        required_failures.update(optional_hard)

    if not healthy:
        message = summarize_probe_failures(required_failures, _FAILURE_MESSAGES)
    elif optional_skipped:
        message = (
            f"Connected to GitHub org '{org_login}' with directory and repository "
            f"access; audit log unavailable ({optional_skipped['audit_log.list']}) — "
            "event policies will be skipped. The audit log API requires GitHub "
            "Enterprise Cloud and the read:audit_log scope."
        )
    else:
        message = f"Connected to GitHub org '{org_login}' with all required API access"

    return HealthCheckResult(healthy=healthy, message=message, checked_permissions=checked)
