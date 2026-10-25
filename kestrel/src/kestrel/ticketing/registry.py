# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Discover TicketProvider implementations (builtins + entry points)."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from kestrel.ticketing.protocol import TicketProvider
from kestrel.ticketing.providers.github_issues import GitHubIssuesProvider
from kestrel.ticketing.providers.jira_cloud import JiraCloudProvider

ENTRY_POINT_GROUP = "kestrel.ticket_providers"

_BUILTINS: dict[str, type] = {
    GitHubIssuesProvider.provider_id: GitHubIssuesProvider,
    JiraCloudProvider.provider_id: JiraCloudProvider,
}


def discover_ticket_providers() -> dict[str, TicketProvider]:
    """Return ``{provider_id: instance}`` for builtins + installed entry points."""
    discovered: dict[str, TicketProvider] = {name: cls() for name, cls in _BUILTINS.items()}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        loaded = ep.load()
        instance: TicketProvider
        instance = loaded() if isinstance(loaded, type) else loaded
        provider_id = getattr(instance, "provider_id", None) or ep.name
        discovered[str(provider_id)] = instance
    return discovered


def load_ticket_provider(provider_id: str) -> TicketProvider:
    providers = discover_ticket_providers()
    if provider_id not in providers:
        available = ", ".join(sorted(providers)) or "(none)"
        raise ValueError(f"Unknown ticket provider {provider_id!r}; available: {available}")
    return providers[provider_id]


def list_provider_ids() -> list[str]:
    return sorted(discover_ticket_providers())


def provider_summaries() -> list[dict[str, Any]]:
    return [
        {
            "id": pid,
            "builtin": pid in _BUILTINS,
        }
        for pid in list_provider_ids()
    ]
