# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Health check: proves the credential can actually read the directory,
rather than only that it exists.

Probes use single-page ``maxResults`` / ``pageSize`` requests so Test
connection does not walk full ``nextPageToken`` pagination on large tenants.

Directory, admin roles, and shared drives are required. Admin Reports
is probed but optional: a Reports permission failure does not
fail Test connection, so operators can still sync identity/drive.
"""

from __future__ import annotations

import logging

from kestrel.connectors.sdk.base import HealthCheckResult
from kestrel.connectors.sdk.failures import (
    FailureMessages,
    classify_http_failure,
    http_status,
    summarize_probe_failures,
)

from kestrel_connector_google_workspace.client import GoogleWorkspaceClient
from kestrel_connector_google_workspace.http import is_rate_limit

_REQUIRED_PROBES = (
    "directory.domain",
    "directory.users",
    "directory.groups",
    "directory.roles",
    "drive.drives",
)


def classify_gws_failure(exc: BaseException) -> str:
    """Map transport/httpx failures to a coarse failure class."""
    status = http_status(exc)
    if status in {401, 403} and not is_rate_limit(exc):
        # Google often returns 403 for bad/missing OAuth scopes or bad SA.
        msg = str(exc).casefold()
        if status == 401 or "invalid_grant" in msg or "unauthorized" in msg:
            return "authentication"
        return "permission"
    return classify_http_failure(exc, is_rate_limit=is_rate_limit)


_FAILURE_MESSAGES = FailureMessages(
    authentication=(
        "Authentication failed for: {probes}. Check service_account_json, delegated_admin_email, and domain-wide delegation."
    ),
    permission=(
        "Permission denied for: {probes}. "
        "Confirm Admin SDK / Drive / Reports scopes on the delegated client ID, "
        "and that delegated_admin_email is Super Admin (or a custom role with "
        "Directory + Drive domain-admin + Reports rights)."
    ),
    rate_limit="Google API rate limit hit for: {probes}. Wait for the quota window or reduce concurrent syncs.",
    network="Network error reaching Google for: {probes}. Check outbound HTTPS from the worker.",
    fallback="Unreachable or missing scopes for: {probes}",
)


logger = logging.getLogger(__name__)


def check_health(client: GoogleWorkspaceClient) -> HealthCheckResult:
    checked: dict[str, bool] = {}
    failures: dict[str, str] = {}

    for label, call in (
        ("directory.domain", client.get_domain),
        ("directory.users", client.probe_users),
        ("directory.groups", client.probe_groups),
        ("directory.roles", client.probe_roles),
        ("drive.drives", client.probe_shared_drives),
        ("reports.login", client.probe_login_activities),
    ):
        try:
            call()
            checked[label] = True
        except Exception as exc:  # deliberately broad: health check classifies any failure into a status
            checked[label] = False
            failures[label] = classify_gws_failure(exc)
            logger.warning("google workspace health probe %s failed (%s)", label, failures[label], exc_info=True)

    required_ok = all(checked.get(label, False) for label in _REQUIRED_PROBES)
    reports_ok = checked.get("reports.login", False)
    if required_ok and reports_ok:
        message = "Google Workspace reachable with all required scopes"
    elif required_ok and not reports_ok:
        reports_class = failures.get("reports.login", "unknown")
        message = (
            "Google Workspace directory, admin roles, and Drive reachable. "
            f"Admin Reports unavailable ({reports_class}): "
            "sync will still collect users/groups/roles/drives. "
            "Grant admin.reports.audit.readonly and a Super Admin (or Reports) "
            "delegated admin to collect audit activity."
        )
    else:
        required_failures = {k: v for k, v in failures.items() if k in _REQUIRED_PROBES}
        message = summarize_probe_failures(required_failures, _FAILURE_MESSAGES)
    return HealthCheckResult(
        healthy=required_ok,
        message=message,
        checked_permissions=checked,
    )
