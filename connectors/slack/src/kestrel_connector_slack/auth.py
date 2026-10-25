# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Live-mode auth for Slack.

Live sync accepts an already-issued bot (xoxb) or — for Enterprise Grid
depth — an org-installed user token (xoxp / xoxe) with Admin + Audit scopes.
Kestrel does not host Slack's OAuth install redirect — mint the token in
Slack and paste it. Fixture mode remains for CI and demos.

Web API calls use ``https://slack.com/api``. Audit Logs use a separate host
(``https://api.slack.com/audit/v1``) with the same Bearer token.
"""

from __future__ import annotations

from kestrel.connectors.sdk.credentials import bearer_headers, first_secret
from kestrel.connectors.sdk.transport import LiveHTTPTransport

SLACK_API_BASE_URL = "https://slack.com/api"
SLACK_AUDIT_BASE_URL = "https://api.slack.com/audit/v1"


class LiveAuthNotConfiguredError(RuntimeError):
    """Raised instead of silently falling back to an unauthenticated client."""


def _token_from_secrets(secrets: dict[str, str]) -> str:
    bot_token = first_secret(secrets, "bot_token", "access_token")
    if not bot_token:
        raise LiveAuthNotConfiguredError(
            "Live Slack sync needs a bot or user token. Provide a 'bot_token' "
            "(or 'access_token') secret, or use sync_mode=fixtures. Enterprise "
            "Grid: org-install as Org Owner and paste the User OAuth Token "
            "(xoxp/xoxe) with all scopes on User Token Scopes — not the Bot "
            "User OAuth Token (xoxb). See docs/connectors/slack-setup.md."
        )
    return bot_token


def build_live_transport(secrets: dict[str, str]) -> LiveHTTPTransport:
    """Builds a live Web API transport from a Slack bot/user token secret."""
    return LiveHTTPTransport(
        base_url=SLACK_API_BASE_URL,
        headers=bearer_headers(_token_from_secrets(secrets)),
    )


def build_audit_transport(secrets: dict[str, str]) -> LiveHTTPTransport:
    """Builds a live Audit Logs transport (separate host, same token)."""
    return LiveHTTPTransport(
        base_url=SLACK_AUDIT_BASE_URL,
        headers=bearer_headers(_token_from_secrets(secrets)),
    )
