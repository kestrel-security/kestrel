# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Health check against org + users + groups + apps + classic admin roles.

Probes use single-page `limit=1` requests so Test connection does not walk
full Link pagination on large orgs. Failures are classified as authentication,
permission, rate_limit, network, or http/unknown for operator-facing messages.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from kestrel.connectors.sdk.base import HealthCheckResult
from kestrel.connectors.sdk.failures import FailureMessages, summarize_probe_failures

from kestrel_connector_okta.client import OktaClient
from kestrel_connector_okta.http import classify_okta_failure


def _fallback_message(probes: str, failures: Mapping[str, str]) -> str:
    if all(c.startswith("http_") or c == "unknown" for c in failures.values()):
        return f"Okta API error for: {probes}"
    return f"Unreachable or missing access for: {probes}"


_FAILURE_MESSAGES = FailureMessages(
    authentication=(
        "Authentication failed (invalid or expired SSWS token) for: {probes}. "
        "Rotate the API token in Admin Console → Security → API → Tokens."
    ),
    permission=(
        "Permission denied for: {probes}. "
        "The token's admin lacks read access to users, groups, apps, or roles. "
        "Prefer Org Admin or Super Admin for a complete inventory (including System Log)."
    ),
    rate_limit="Okta rate limit hit for: {probes}. Wait for the reset window; live sync retries HTTP 429 a few times.",
    network="Network error reaching Okta for: {probes}. Check org_url, DNS, and outbound HTTPS from the worker.",
    fallback=_fallback_message,
)


def _first_user_id(payload: Any) -> str | None:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        nested = payload.get("users")
        rows = nested if isinstance(nested, list) else [payload]
    else:
        return None
    for row in rows:
        if isinstance(row, dict) and row.get("id"):
            return str(row["id"])
    return None


logger = logging.getLogger(__name__)


def check_health(client: OktaClient) -> HealthCheckResult:
    checked: dict[str, bool] = {}
    failures: dict[str, str] = {}

    for label, call in (
        ("org.settings", client.get_org),
        ("users.list", client.probe_users),
        ("groups.list", client.probe_groups),
        ("apps.list", client.probe_apps),
    ):
        try:
            result = call()
            checked[label] = True
            if label == "users.list":
                user_id = _first_user_id(result)
                if user_id:
                    try:
                        client.probe_user_roles(user_id)
                        checked["users.roles"] = True
                    except Exception as exc:  # deliberately broad: health check classifies any failure into a status
                        checked["users.roles"] = False
                        failures["users.roles"] = classify_okta_failure(exc)
                        logger.warning("okta health probe users.roles failed (%s)", failures["users.roles"], exc_info=True)
                else:
                    checked["users.roles"] = True
        except Exception as exc:  # deliberately broad: health check classifies any failure into a status
            checked[label] = False
            failures[label] = classify_okta_failure(exc)
            logger.warning("okta health probe %s failed (%s)", label, failures[label], exc_info=True)
            if label == "users.list":
                checked["users.roles"] = False
                failures["users.roles"] = failures[label]

    try:
        client.probe_logs()
        checked["logs.list"] = True
    except Exception as exc:  # deliberately broad: health check classifies any failure into a status
        klass = classify_okta_failure(exc)
        logger.warning("okta health probe logs.list failed (%s)", klass, exc_info=True)
        checked["logs.list"] = False
        failures["logs.list"] = klass

    required_ok = all(ok for label, ok in checked.items() if label != "logs.list")
    logs_optional_skip = (not checked.get("logs.list", False)) and failures.get("logs.list") in {
        "permission",
        "http_404",
    }
    healthy = required_ok and (checked.get("logs.list", False) or logs_optional_skip)
    if healthy and logs_optional_skip:
        message = (
            "Okta reachable with directory access; System Log unavailable "
            f"({failures['logs.list']}) — event policies will be skipped until "
            "the token can read /api/v1/logs."
        )
    elif healthy:
        message = "Okta reachable with required API access"
    else:
        message = summarize_probe_failures(failures, _FAILURE_MESSAGES)
    return HealthCheckResult(
        healthy=healthy,
        message=message,
        checked_permissions=checked,
    )
