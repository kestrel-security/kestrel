# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Helpers for emitting tenant `setting` NormalizedObjects."""

from __future__ import annotations

from typing import Any

from kestrel.connectors.sdk.base import NormalizedObject


def setting_object(
    *,
    key: str,
    category: str,
    label: str,
    value: Any,
    value_type: str,
    description: str | None = None,
    raw_source: dict[str, Any] | None = None,
    provider_id_prefix: str = "org-setting",
    subject_type: str | None = None,
    subject_ref: str | None = None,
) -> NormalizedObject:
    """Emit a tenant or subject-scoped setting.

    Subject-scoped settings (per-repo, per-OU, per-device) set
    ``subject_type`` + ``subject_ref`` so the upsert resolves them to the
    owning entity. Categories that the Changes classifier treats as
    sensitive: ``security``, ``sharing``, ``access``.
    """
    attributes: dict[str, Any] = {
        "key": key,
        "category": category,
        "label": label,
        "value": value,
        "value_type": value_type,
        "description": description,
    }
    if subject_type is not None and subject_ref is not None:
        attributes["subject_type"] = subject_type
        attributes["subject_ref"] = subject_ref
    return NormalizedObject(
        kind="setting",
        provider_id=f"{provider_id_prefix}:{key}",
        attributes=attributes,
        raw_source=raw_source or {"key": key, "value": value},
    )


def alert_count_setting(
    *,
    key: str,
    label: str,
    count: int,
    subject_type: str,
    subject_ref: str,
    description: str | None = None,
    raw_source: dict[str, Any] | None = None,
    provider_id_prefix: str = "alert-count",
) -> NormalizedObject:
    """Open-alert count by severity/type — bodies are never stored.

    Follows the GitHub ``repo_open_secret_scanning_alerts`` pattern: a
    subject-scoped integer setting under category ``security``.
    """
    return setting_object(
        key=key,
        category="security",
        label=label,
        value=int(count),
        value_type="integer",
        description=description or "Open alert count (bodies are not stored).",
        raw_source=raw_source or {"key": key, "count": int(count)},
        provider_id_prefix=provider_id_prefix,
        subject_type=subject_type,
        subject_ref=subject_ref,
    )


def settings_from_mapping(
    payload: dict[str, Any],
    specs: list[tuple[str, str, str, str, str | None]],
    *,
    provider_id_prefix: str = "org-setting",
) -> list[NormalizedObject]:
    """Emit settings for keys present in payload.

    Each spec is ``(key, category, label, value_type, description)``.
    """
    out: list[NormalizedObject] = []
    for key, category, label, value_type, description in specs:
        if key not in payload:
            continue
        value = payload[key]
        out.append(
            setting_object(
                key=key,
                category=category,
                label=label,
                value=value,
                value_type=value_type,
                description=description,
                raw_source={"key": key, "value": value, "source": payload},
                provider_id_prefix=provider_id_prefix,
            )
        )
    return out
