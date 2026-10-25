# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator saved findings filter presets."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.db.models.finding_preset import FindingFilterPreset
from kestrel.findings.investigation.status import FindingInvestigationError
from kestrel.findings.listing import FindingListError, apply_finding_filters

# Keep lists bounded so one noisy operator cannot grow unbounded.
PRESET_LIMIT = 50
FAVORITE_LIMIT = 50

ALLOWED_FILTER_KEYS = frozenset(
    {
        "status",
        "severity",
        "search",
        "policy_slug",
        "policy_version_id",
        "assigned_to_operator_id",
        "unassigned",
        "open_older_than_days",
        "subject_id",
        "subject_type",
        "application_instance_id",
    }
)


class FindingPresetError(ValueError):
    """Invalid preset name or filter payload."""


def _serialize(row: FindingFilterPreset) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "filters": dict(row.filters or {}),
        "is_favorite": row.is_favorite,
        "last_used_at": row.last_used_at.isoformat(),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def normalize_filters(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Sparse, validated filter dict suitable for storage and URL rebuild."""
    if raw is None:
        raise FindingPresetError("filters is required")
    if not isinstance(raw, dict):
        raise FindingPresetError("filters must be an object")

    unknown = set(raw) - ALLOWED_FILTER_KEYS
    if unknown:
        raise FindingPresetError(f"unsupported filter keys: {', '.join(sorted(unknown))}")

    out: dict[str, Any] = {}

    def _str(key: str, *, max_len: int = 500) -> None:
        if key not in raw or raw[key] is None:
            return
        val = raw[key]
        if not isinstance(val, str):
            raise FindingPresetError(f"{key} must be a string")
        text = val.strip()
        if not text:
            return
        if len(text) > max_len:
            raise FindingPresetError(f"{key} is too long")
        out[key] = text

    _str("status", max_len=32)
    _str("severity", max_len=32)
    _str("search", max_len=200)
    _str("policy_slug", max_len=200)
    _str("policy_version_id", max_len=36)
    _str("assigned_to_operator_id", max_len=36)
    _str("subject_id", max_len=36)
    _str("subject_type", max_len=32)
    _str("application_instance_id", max_len=36)

    if "unassigned" in raw and raw["unassigned"] is not None:
        val = raw["unassigned"]
        if isinstance(val, bool):
            if val:
                out["unassigned"] = True
        elif isinstance(val, str) and val.strip().lower() in {"true", "1", "yes"}:
            out["unassigned"] = True
        elif isinstance(val, str) and val.strip().lower() in {"false", "0", "no"}:
            pass
        else:
            raise FindingPresetError("unassigned must be a boolean")

    if "open_older_than_days" in raw and raw["open_older_than_days"] is not None:
        days = raw["open_older_than_days"]
        if isinstance(days, str) and days.strip().isdigit():
            days = int(days.strip())
        if not isinstance(days, int) or isinstance(days, bool):
            raise FindingPresetError("open_older_than_days must be an integer >= 1")
        if days < 1:
            raise FindingPresetError("open_older_than_days must be >= 1")
        out["open_older_than_days"] = days

    if out.get("unassigned") and "assigned_to_operator_id" in out:
        raise FindingPresetError("unassigned cannot be combined with assigned_to_operator_id")

    try:
        if "assigned_to_operator_id" in out:
            uuid.UUID(out["assigned_to_operator_id"])
        if "policy_version_id" in out:
            uuid.UUID(out["policy_version_id"])
        if "subject_id" in out:
            uuid.UUID(out["subject_id"])
        if "application_instance_id" in out:
            uuid.UUID(out["application_instance_id"])
    except ValueError as exc:
        raise FindingPresetError("filter UUID fields must be valid UUIDs") from exc

    if out.get("open_older_than_days") is not None:
        status = out.get("status")
        if status is not None and status.lower() != "open":
            raise FindingPresetError("open_older_than_days only applies to open findings")

    return out


def list_presets(db: Session, *, org_id: uuid.UUID, operator_id: uuid.UUID) -> dict:
    """Return favorites (newest first) and recent non-favorites."""
    favorites = list(
        db.scalars(
            select(FindingFilterPreset)
            .where(
                FindingFilterPreset.org_id == org_id,
                FindingFilterPreset.operator_id == operator_id,
                FindingFilterPreset.is_favorite.is_(True),
            )
            .order_by(FindingFilterPreset.last_used_at.desc())
            .limit(FAVORITE_LIMIT)
        ).all()
    )
    recent = list(
        db.scalars(
            select(FindingFilterPreset)
            .where(
                FindingFilterPreset.org_id == org_id,
                FindingFilterPreset.operator_id == operator_id,
                FindingFilterPreset.is_favorite.is_(False),
            )
            .order_by(FindingFilterPreset.last_used_at.desc())
            .limit(PRESET_LIMIT)
        ).all()
    )
    return {
        "favorites": [_serialize(r) for r in favorites],
        "recent": [_serialize(r) for r in recent],
    }


def create_or_update_preset(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    name: str,
    filters: dict[str, Any],
) -> FindingFilterPreset:
    """Upsert by (org, operator, name). Explicit save only — no auto-record."""
    label = name.strip()
    if not label:
        raise FindingPresetError("name must not be empty")
    if len(label) > 120:
        raise FindingPresetError("name must be at most 120 characters")

    normalized = normalize_filters(filters)
    validate_filters_against_listing(db, org_id, normalized)
    now = datetime.now(UTC)
    existing = db.scalars(
        select(FindingFilterPreset).where(
            FindingFilterPreset.org_id == org_id,
            FindingFilterPreset.operator_id == operator_id,
            FindingFilterPreset.name == label,
        )
    ).first()
    if existing is not None:
        existing.filters = normalized
        existing.last_used_at = now
        db.flush()
        return existing

    count = db.scalar(
        select(func.count())
        .select_from(FindingFilterPreset)
        .where(
            FindingFilterPreset.org_id == org_id,
            FindingFilterPreset.operator_id == operator_id,
        )
    )
    if (count or 0) >= PRESET_LIMIT:
        raise FindingPresetError(f"preset limit of {PRESET_LIMIT} reached")

    row = FindingFilterPreset(
        id=uuid.uuid4(),
        org_id=org_id,
        operator_id=operator_id,
        name=label,
        filters=normalized,
        is_favorite=False,
        last_used_at=now,
    )
    db.add(row)
    db.flush()
    return row


def update_preset(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    preset_id: uuid.UUID,
    name: str | None = None,
    filters: dict[str, Any] | None = None,
    is_favorite: bool | None = None,
) -> FindingFilterPreset | None:
    row = db.get(FindingFilterPreset, preset_id)
    if row is None or row.org_id != org_id or row.operator_id != operator_id:
        return None

    if name is not None:
        label = name.strip()
        if not label:
            raise FindingPresetError("name must not be empty")
        if len(label) > 120:
            raise FindingPresetError("name must be at most 120 characters")
        clash = db.scalars(
            select(FindingFilterPreset).where(
                FindingFilterPreset.org_id == org_id,
                FindingFilterPreset.operator_id == operator_id,
                FindingFilterPreset.name == label,
                FindingFilterPreset.id != preset_id,
            )
        ).first()
        if clash is not None:
            raise FindingPresetError("a preset with that name already exists")
        row.name = label

    if filters is not None:
        normalized = normalize_filters(filters)
        validate_filters_against_listing(db, org_id, normalized)
        row.filters = normalized

    if is_favorite is not None:
        if is_favorite and not row.is_favorite:
            fav_count = db.scalar(
                select(func.count())
                .select_from(FindingFilterPreset)
                .where(
                    FindingFilterPreset.org_id == org_id,
                    FindingFilterPreset.operator_id == operator_id,
                    FindingFilterPreset.is_favorite.is_(True),
                )
            )
            if (fav_count or 0) >= FAVORITE_LIMIT:
                raise FindingPresetError(f"favorite limit of {FAVORITE_LIMIT} reached")
        row.is_favorite = is_favorite

    row.last_used_at = datetime.now(UTC)
    db.flush()
    return row


def touch_preset(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    preset_id: uuid.UUID,
) -> FindingFilterPreset | None:
    row = db.get(FindingFilterPreset, preset_id)
    if row is None or row.org_id != org_id or row.operator_id != operator_id:
        return None
    row.last_used_at = datetime.now(UTC)
    db.flush()
    return row


def delete_preset(
    db: Session,
    *,
    org_id: uuid.UUID,
    operator_id: uuid.UUID,
    preset_id: uuid.UUID,
) -> bool:
    row = db.get(FindingFilterPreset, preset_id)
    if row is None or row.org_id != org_id or row.operator_id != operator_id:
        return False
    db.delete(row)
    db.flush()
    return True


def validate_filters_against_listing(
    db: Session,
    org_id: uuid.UUID,
    filters: dict[str, Any],
) -> None:
    """Run list-filter semantics so bad presets fail at save time.

    `filters` should already be normalized (or normalize_filters-compatible).
    """
    normalized = normalize_filters(filters)
    try:
        assignee = uuid.UUID(normalized["assigned_to_operator_id"]) if "assigned_to_operator_id" in normalized else None
        policy_version_id = uuid.UUID(normalized["policy_version_id"]) if "policy_version_id" in normalized else None
        subject_id = uuid.UUID(normalized["subject_id"]) if "subject_id" in normalized else None
        application_instance_id = (
            uuid.UUID(normalized["application_instance_id"]) if "application_instance_id" in normalized else None
        )
        stmt = select(Finding).where(Finding.org_id == org_id)
        apply_finding_filters(
            stmt,
            db,
            org_id,
            status=normalized.get("status"),
            severity=normalized.get("severity"),
            search=normalized.get("search"),
            policy_version_id=policy_version_id,
            policy_slug=normalized.get("policy_slug"),
            assigned_to_operator_id=assignee,
            unassigned=True if normalized.get("unassigned") else None,
            open_older_than_days=normalized.get("open_older_than_days"),
            subject_id=subject_id,
            subject_type=normalized.get("subject_type"),
            application_instance_id=application_instance_id,
        )
    except (FindingListError, FindingInvestigationError) as exc:
        raise FindingPresetError(str(exc)) from exc
