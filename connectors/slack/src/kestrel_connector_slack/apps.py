# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Normalize Slack Admin Apps payloads (fixture-flat vs live nested).

Live ``admin.apps.approved.list`` returns ``{app: {...}, scopes: [{name, token_type,
is_sensitive}], last_resolved_by, date_updated}``. Bundled fixtures store a
flattened shape (``app_id``, ``scopes.bot`` / ``scopes.user``,
``installer_user_id``). Collectors flatten once so the normalizer stays a
pure mapping.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.payload import sub_dict


# Admin Apps APIs are Enterprise Grid (org-install + admin.apps:read). These
# errors mean "skip OAuth inventory, keep members/groups/roles".
def _unix_to_iso(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str) and not value.isdigit():
        return value
    try:
        ts: float = int(value)
    except (TypeError, ValueError):
        return None
    if ts > 10_000_000_000:
        # Some Slack fields are milliseconds; fromtimestamp takes seconds.
        ts = ts / 1000
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def flatten_approved_app(item: dict[str, Any]) -> dict[str, Any]:
    """Return a fixture-compatible app dict from a live or fixture item."""
    nested = item.get("app")
    if isinstance(nested, dict):
        developer = nested.get("developer_type")
        last_resolved = item.get("last_resolved_by") or {}
        installer = None
        if isinstance(last_resolved, dict):
            installer = last_resolved.get("actor_id")
        bot, user, flags = _scopes_from_live_list(item.get("scopes") or [])
        return {
            "app_id": str(nested.get("id") or ""),
            "id": nested.get("id"),
            "name": nested.get("name"),
            "publisher": developer if isinstance(developer, str) else None,
            "is_app_directory_approved": nested.get("is_app_directory_approved"),
            "is_internal": nested.get("is_internal"),
            "developer_type": developer,
            "installer_user_id": installer or item.get("installer_user_id"),
            "scopes": {"bot": bot, "user": user},
            "scope_sensitivity": flags,
            "date_updated": item.get("date_updated"),
            "date_installed": _unix_to_iso(item.get("date_updated")),
            "last_resolved_by": last_resolved if isinstance(last_resolved, dict) else {},
        }

    scopes = item.get("scopes") or {}
    flags = dict(item.get("scope_sensitivity") or {})
    if isinstance(scopes, list):
        bot, user, flags = _scopes_from_live_list(scopes)
        scopes = {"bot": bot, "user": user}
    out = dict(item)
    out["app_id"] = str(item.get("app_id") or item.get("id") or "")
    out["scopes"] = scopes
    out["scope_sensitivity"] = flags
    return out


def _scopes_from_live_list(scopes: Any) -> tuple[list[str], list[str], dict[str, bool]]:
    bot: list[str] = []
    user: list[str] = []
    flags: dict[str, bool] = {}
    if not isinstance(scopes, list):
        return bot, user, flags
    for entry in scopes:
        if isinstance(entry, str):
            bot.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if not name:
            continue
        token_type = str(entry.get("token_type") or "bot").casefold()
        if token_type == "user":
            user.append(name)
        else:
            bot.append(name)
        if "is_sensitive" in entry:
            flags[name] = bool(entry["is_sensitive"])
    return bot, user, flags


def scope_names(app: dict[str, Any]) -> list[tuple[str, bool | None]]:
    """Return (scope_name, slack_is_sensitive_or_None) pairs, bot then user."""
    flags = sub_dict(app, "scope_sensitivity")
    scopes = app.get("scopes") or {}
    names: list[str] = []
    if isinstance(scopes, dict):
        names.extend(str(s) for s in (scopes.get("bot") or []))
        names.extend(str(s) for s in (scopes.get("user") or []))
    elif isinstance(scopes, list):
        for entry in scopes:
            if isinstance(entry, str):
                names.append(entry)
            elif isinstance(entry, dict) and entry.get("name"):
                names.append(str(entry["name"]))
                if "is_sensitive" in entry:
                    flags[str(entry["name"])] = bool(entry["is_sensitive"])
    seen: set[str] = set()
    out: list[tuple[str, bool | None]] = []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        flag = flags.get(name)
        out.append((name, bool(flag) if flag is not None else None))
    return out


def installation_from_approved_app(app: dict[str, Any]) -> dict[str, Any] | None:
    """Build an oauth_grant-shaped payload when Admin Apps has no installations API."""
    app_id = str(app.get("app_id") or app.get("id") or "")
    user_id = app.get("installer_user_id")
    if not app_id or not user_id:
        return None
    return {
        "app_id": app_id,
        "user_id": str(user_id),
        "date_installed": app.get("date_installed") or _unix_to_iso(app.get("date_updated")),
        "last_active": app.get("last_active"),
        "last_used_at": app.get("last_used_at"),
    }
