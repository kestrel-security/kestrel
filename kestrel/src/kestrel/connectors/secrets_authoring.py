# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Validate and persist connector secrets for the Builder UI / API.

Plaintext is accepted only on write; responses expose field names and
configured/missing status — never ciphertext or decrypted values.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.connectors.authoring import ConnectorAuthoringError
from kestrel.db.models.connector import Connector, ConnectorInstance
from kestrel.secrets.store import list_configured_secret_fields, set_secret

# Keys that must never appear as non-empty strings inside instance.config.
_SECRETISH_CONFIG_KEYS = frozenset(
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
    }
)


def reject_secrets_in_config(config: dict[str, Any], *, prefix: str = "config") -> None:
    """Reject plaintext credentials smuggled into config JSON."""
    for key, value in config.items():
        lowered = key.lower().replace("-", "_")
        if lowered in _SECRETISH_CONFIG_KEYS and isinstance(value, str) and value.strip():
            raise ConnectorAuthoringError(
                f"{prefix}.{key} looks like a secret — put credentials under secrets (ConnectorSecret), never in config"
            )
        if isinstance(value, dict):
            reject_secrets_in_config(value, prefix=f"{prefix}.{key}")


def declared_secret_fields(connector: Connector, auth_method: str) -> list[str]:
    """Manifest secret_fields for the instance's auth method (stable order)."""
    manifest = connector.manifest or {}
    methods = manifest.get("auth_methods") or []
    for method in methods:
        if not isinstance(method, dict):
            continue
        if str(method.get("id")) == auth_method:
            fields = method.get("secret_fields") or []
            return [str(f) for f in fields if str(f).strip()]
    # Fall back to union across methods when auth id is unknown / legacy.
    seen: list[str] = []
    for method in methods:
        if not isinstance(method, dict):
            continue
        for field in method.get("secret_fields") or []:
            name = str(field).strip()
            if name and name not in seen:
                seen.append(name)
    return seen


def declared_config_fields(connector: Connector, auth_method: str) -> list[str]:
    manifest = connector.manifest or {}
    methods = manifest.get("auth_methods") or []
    for method in methods:
        if not isinstance(method, dict):
            continue
        if str(method.get("id")) == auth_method:
            fields = method.get("config_fields") or []
            return [str(f) for f in fields if str(f).strip()]
    example = manifest.get("example_config") or {}
    return [str(k) for k in example] if isinstance(example, dict) else []


def secret_status(
    session: Session,
    *,
    connector: Connector,
    instance: ConnectorInstance,
) -> dict[str, Any]:
    declared = declared_secret_fields(connector, instance.auth_method.value)
    configured = list_configured_secret_fields(session, connector_instance_id=instance.id)
    configured_set = set(configured)
    return {
        "declared_fields": declared,
        "configured_fields": configured,
        "missing_fields": [f for f in declared if f not in configured_set],
        "fields": [
            {
                "name": name,
                "configured": name in configured_set,
            }
            for name in declared
        ],
    }


def upsert_secrets(
    session: Session,
    *,
    org_id: uuid.UUID,
    instance: ConnectorInstance,
    connector: Connector,
    secrets: dict[str, str],
    require_all_declared: bool = False,
) -> dict[str, Any]:
    """Encrypt and upsert secrets. Empty / whitespace values are ignored
    (edit form: leave blank to keep). Never returns plaintext."""
    if not isinstance(secrets, dict):
        raise ConnectorAuthoringError("secrets must be an object of field → string")

    allowed = set(declared_secret_fields(connector, instance.auth_method.value))
    if not allowed and secrets:
        raise ConnectorAuthoringError(
            f"Connector does not declare secret_fields for auth_method '{instance.auth_method.value}'"
        )

    cleaned: dict[str, str] = {}
    for raw_key, raw_val in secrets.items():
        key = str(raw_key).strip()
        if not key:
            continue
        if key not in allowed:
            raise ConnectorAuthoringError(f"Unknown secret field '{key}'. Allowed: {', '.join(sorted(allowed)) or '(none)'}")
        if not isinstance(raw_val, str):
            raise ConnectorAuthoringError(f"Secret '{key}' must be a string")
        if not raw_val.strip():
            continue
        # Preserve formatting for JSON key material; trim scalar tokens.
        cleaned[key] = raw_val if key.endswith("_json") else raw_val.strip()

    if require_all_declared:
        already = set(list_configured_secret_fields(session, connector_instance_id=instance.id))
        still_missing = [f for f in sorted(allowed) if f not in cleaned and f not in already]
        if still_missing:
            raise ConnectorAuthoringError("Live mode requires secrets for: " + ", ".join(still_missing))

    for field_name, plaintext in cleaned.items():
        set_secret(
            session,
            org_id=org_id,
            connector_instance_id=instance.id,
            field_name=field_name,
            plaintext_value=plaintext,
        )

    return secret_status(session, connector=connector, instance=instance)
