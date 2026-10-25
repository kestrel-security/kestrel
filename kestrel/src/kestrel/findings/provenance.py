# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding subject provenance / raw_source browser.

Returns the subject's stored provider payload for investigation, with
secret-field redaction and trim-tombstone awareness. Never decrypts
connector secrets — only redacts keys that look like credentials.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.finding import Finding, FindingSubjectType
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.resource import Resource
from kestrel.db.models.setting import TenantSetting
from kestrel.retention.raw_source import TOMBSTONE_KEY, is_trimmed
from kestrel.secrets.store import REDACTED_PLACEHOLDER, redact

# Keys scrubbed from provenance payloads before API/UI (defense in depth).
_DEFAULT_SECRET_FIELDS = frozenset(
    {
        "token",
        "pat",
        "password",
        "secret",
        "api_key",
        "apikey",
        "api_token",
        "ssws_token",
        "client_secret",
        "private_key",
        "access_token",
        "refresh_token",
        "bot_token",
        "service_account_json",
        "authorization",
    }
)

_MAX_SERIALIZED_BYTES = 256_000


def _load_subject_entity(db: Session, finding: Finding) -> tuple[Any | None, str | None]:
    """Return (entity_or_none, missing_reason)."""
    subject_type = finding.subject_type
    subject_id = finding.subject_id

    if subject_type == FindingSubjectType.IDENTITY:
        identity = db.get(Identity, subject_id)
        if identity is None or identity.org_id != finding.org_id:
            return None, "subject_not_found"
        return identity, None

    if subject_type == FindingSubjectType.RESOURCE:
        resource = db.get(Resource, subject_id)
        if resource is None or resource.org_id != finding.org_id:
            return None, "subject_not_found"
        return resource, None

    if subject_type == FindingSubjectType.OAUTH_APPLICATION:
        oauth_app = db.get(OAuthApplication, subject_id)
        if oauth_app is None or oauth_app.org_id != finding.org_id:
            return None, "subject_not_found"
        return oauth_app, None

    if subject_type == FindingSubjectType.SETTING:
        setting = db.get(TenantSetting, subject_id)
        if setting is None or setting.org_id != finding.org_id:
            return None, "subject_not_found"
        return setting, None

    if subject_type == FindingSubjectType.EVENT:
        event = db.get(ActivityEvent, subject_id)
        if event is None or event.org_id != finding.org_id:
            return None, "subject_not_found"
        return event, None

    if subject_type == FindingSubjectType.APPLICATION:
        application = db.get(ApplicationInstance, subject_id)
        if application is None or application.org_id != finding.org_id:
            return None, "subject_not_found"
        return application, None

    return None, "unsupported_subject_type"


def _approx_bytes(payload: Any) -> int:
    try:
        return len(json.dumps(payload, default=str))
    except (TypeError, ValueError):
        return 0


def _truncate_if_needed(payload: Any) -> tuple[Any, bool]:
    size = _approx_bytes(payload)
    if size <= _MAX_SERIALIZED_BYTES:
        return payload, False
    return {
        "_kestrel_provenance_truncated": True,
        "approx_bytes": size,
        "message": f"Payload exceeds {_MAX_SERIALIZED_BYTES} bytes; open via export or trim retention.",
        "preview_keys": list(payload.keys())[:50] if isinstance(payload, dict) else [],
    }, True


def finding_provenance(db: Session, finding: Finding) -> dict[str, Any]:
    """Build provenance payload for a finding's subject (org-scoped)."""
    entity, missing = _load_subject_entity(db, finding)
    base = {
        "finding_id": str(finding.id),
        "subject_type": finding.subject_type.value,
        "subject_id": str(finding.subject_id),
        "available": False,
        "trimmed": False,
        "truncated": False,
        "approx_bytes": 0,
        "last_seen_at": None,
        "first_seen_at": None,
        "raw_source": None,
        "message": None,
    }
    if entity is None:
        return {**base, "message": missing or "subject_not_found"}

    # ApplicationInstance has no provider raw_source — synthesize remediator metadata.
    if finding.subject_type == FindingSubjectType.APPLICATION and isinstance(entity, ApplicationInstance):
        catalog = db.get(Application, entity.application_id)
        synthetic = {
            "display_name": entity.display_name,
            "external_tenant_ref": entity.external_tenant_ref,
            "status": entity.status.value if entity.status else None,
            "application_type": catalog.application_type.value if catalog else None,
            "application_name": catalog.name if catalog else None,
        }
        return {
            **base,
            "available": True,
            "approx_bytes": _approx_bytes(synthetic),
            "raw_source": synthetic,
            "message": "application_instance_metadata",
        }

    raw = getattr(entity, "raw_source", None)
    if not isinstance(raw, dict):
        return {**base, "message": "no_raw_source"}

    last_seen = getattr(entity, "last_seen_at", None)
    first_seen = getattr(entity, "first_seen_at", None)
    trimmed = is_trimmed(raw)
    if trimmed:
        return {
            **base,
            "available": True,
            "trimmed": True,
            "approx_bytes": _approx_bytes(raw),
            "last_seen_at": last_seen.isoformat() if last_seen else None,
            "first_seen_at": first_seen.isoformat() if first_seen else None,
            "raw_source": {
                TOMBSTONE_KEY: True,
                "trimmed_at": raw.get("trimmed_at"),
            },
            "message": "raw_source_trimmed",
        }

    redacted = redact(raw, set(_DEFAULT_SECRET_FIELDS))
    # Also scrub any key containing secret-ish substrings.
    if isinstance(redacted, dict):
        scrubbed: dict[str, Any] = {}
        for key, val in redacted.items():
            lowered = str(key).lower().replace("-", "_")
            if any(s in lowered for s in ("secret", "password", "token", "private_key")):
                scrubbed[key] = REDACTED_PLACEHOLDER
            else:
                scrubbed[key] = val
        redacted = scrubbed

    payload, truncated = _truncate_if_needed(redacted)
    return {
        **base,
        "available": True,
        "trimmed": False,
        "truncated": truncated,
        "approx_bytes": _approx_bytes(redacted),
        "last_seen_at": last_seen.isoformat() if last_seen else None,
        "first_seen_at": first_seen.isoformat() if first_seen else None,
        "raw_source": payload,
        "message": "truncated" if truncated else None,
    }


def finding_provenance_for_org(
    db: Session,
    *,
    org_id: uuid.UUID,
    finding_id: uuid.UUID,
) -> dict[str, Any] | None:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.org_id != org_id:
        return None
    return finding_provenance(db, finding)
