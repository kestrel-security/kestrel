# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Create/update helpers for ticket integrations (shared by the API router)."""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.ticket import BUILTIN_TICKET_PROVIDERS, GITHUB_ISSUES, JIRA_CLOUD, TicketIntegration
from kestrel.secrets.crypto import EnvKeyProvider, KeyProvider, decrypt_secret, encrypt_secret, secret_context
from kestrel.security.ssrf import UnsafeConnectorURLError, changed_endpoint_fields, validate_connector_url
from kestrel.ticketing.registry import list_provider_ids

_NAME_RE = re.compile(r"^[\w .'/:-]{1,120}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class TicketAuthoringError(ValueError):
    """Invalid ticket integration input."""


def validate_name(name: str) -> str:
    cleaned = name.strip()
    if not _NAME_RE.match(cleaned):
        raise TicketAuthoringError("name must be 1–120 characters (letters, digits, spaces, and ._'/: -)")
    return cleaned


def validate_provider(provider: str) -> str:
    cleaned = provider.strip()
    known = set(list_provider_ids()) | set(BUILTIN_TICKET_PROVIDERS)
    if cleaned not in known:
        raise TicketAuthoringError(f"unsupported provider {cleaned!r}; supported: {', '.join(sorted(known))}")
    return cleaned


def normalize_config(provider: str, config: dict[str, Any] | None) -> dict[str, Any]:
    raw = dict(config or {})
    if provider == GITHUB_ISSUES:
        repo = raw.get("repo") or raw.get("github_repo")
        if not isinstance(repo, str) or not repo.strip():
            raise TicketAuthoringError("config.repo is required for github_issues (owner/repo)")
        cleaned = repo.strip()
        cleaned = cleaned.removeprefix("https://github.com/").removeprefix("http://github.com/")
        cleaned = cleaned.removesuffix(".git").strip("/")
        if not _REPO_RE.match(cleaned):
            raise TicketAuthoringError("config.repo must look like owner/repo")
        return {"repo": cleaned}

    if provider == JIRA_CLOUD:
        base = raw.get("base_url") or raw.get("jira_base_url")
        if not isinstance(base, str) or not base.strip():
            raise TicketAuthoringError("config.base_url is required for jira_cloud")
        from urllib.parse import urlparse

        cleaned_base = base.strip().rstrip("/")
        parsed = urlparse(cleaned_base)
        if parsed.scheme and parsed.netloc:
            cleaned_base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            validate_connector_url(cleaned_base, field="base_url", require_https=True)
        except UnsafeConnectorURLError as exc:
            raise TicketAuthoringError(str(exc)) from exc
        project_key = raw.get("project_key")
        if not isinstance(project_key, str) or not project_key.strip():
            raise TicketAuthoringError("config.project_key is required for jira_cloud")
        email = raw.get("email") or raw.get("jira_email")
        if not isinstance(email, str) or not email.strip():
            raise TicketAuthoringError("config.email is required for jira_cloud")
        issue_type = raw.get("issue_type")
        out: dict[str, Any] = {
            "base_url": cleaned_base,
            "project_key": project_key.strip(),
            "email": email.strip(),
        }
        if isinstance(issue_type, str) and issue_type.strip():
            out["issue_type"] = issue_type.strip()
        return out

    # Entry-point providers: store config as-is (must be a JSON object).
    return raw


def validate_token(token: str) -> str:
    cleaned = token.strip()
    if len(cleaned) < 8:
        raise TicketAuthoringError("api_token must be at least 8 characters")
    if len(cleaned) > 4096:
        raise TicketAuthoringError("api_token is too long")
    return cleaned


def integration_secret_context(integration_id: uuid.UUID) -> bytes:
    """Associated data binding an API token to its integration row."""
    return secret_context(TicketIntegration.__tablename__, integration_id, "secret")


def _store_token(integration: TicketIntegration, key_provider: KeyProvider, api_token: str) -> None:
    encrypted = encrypt_secret(
        key_provider, integration.org_id, validate_token(api_token), context=integration_secret_context(integration.id)
    )
    integration.secret_ciphertext = encrypted.ciphertext
    integration.secret_nonce = encrypted.nonce
    integration.secret_key_version = encrypted.key_version


def create_integration(
    session: Session,
    *,
    org_id: uuid.UUID,
    name: str,
    provider: str,
    api_token: str,
    config: dict[str, Any] | None = None,
    description: str | None = None,
    key_provider: KeyProvider | None = None,
) -> TicketIntegration:
    provider_id = validate_provider(provider)
    kp = key_provider or EnvKeyProvider()
    row_id = uuid.uuid4()
    encrypted = encrypt_secret(kp, org_id, validate_token(api_token), context=integration_secret_context(row_id))
    row = TicketIntegration(
        id=row_id,
        org_id=org_id,
        name=validate_name(name),
        provider=provider_id,
        description=description.strip() if description else None,
        config=normalize_config(provider_id, config),
        secret_ciphertext=encrypted.ciphertext,
        secret_nonce=encrypted.nonce,
        secret_key_version=encrypted.key_version,
        is_enabled=True,
    )
    session.add(row)
    session.flush()
    return row


def update_integration(
    session: Session,
    integration: TicketIntegration,
    *,
    name: str | None = None,
    config: dict[str, Any] | None = None,
    description: str | None = None,
    is_enabled: bool | None = None,
    description_set: bool = False,
    api_token: str | None = None,
    key_provider: KeyProvider | None = None,
) -> TicketIntegration:
    """Update an integration in place.

    The stored token never follows the integration to a new host: when the
    config changes where requests go (``base_url`` / any URL-valued key), the
    caller must send ``api_token`` in the same update, or it is rejected.
    """
    if name is not None:
        integration.name = validate_name(name)
    if config is not None:
        normalized = normalize_config(integration.provider, config)
        endpoint_changes = changed_endpoint_fields(integration.config, normalized)
        has_token = api_token is not None and bool(api_token.strip())
        if endpoint_changes and not has_token:
            raise TicketAuthoringError(
                f"{', '.join(endpoint_changes)} changed: re-enter api_token in the same request "
                "(the stored token is not sent to a new host)"
            )
        integration.config = normalized
    if api_token is not None and api_token.strip():
        kp = key_provider or EnvKeyProvider()
        _store_token(integration, kp, api_token)
    if description_set:
        integration.description = description.strip() if description else None
    if is_enabled is not None:
        integration.is_enabled = is_enabled
    session.flush()
    return integration


def rotate_token(
    session: Session,
    integration: TicketIntegration,
    *,
    api_token: str,
    key_provider: KeyProvider | None = None,
) -> None:
    kp = key_provider or EnvKeyProvider()
    _store_token(integration, kp, api_token)
    session.flush()


def decrypt_integration_token(
    integration: TicketIntegration,
    *,
    key_provider: KeyProvider | None = None,
) -> str:
    kp = key_provider or EnvKeyProvider()
    return decrypt_secret(
        kp,
        integration.org_id,
        integration.secret_ciphertext,
        integration.secret_nonce,
        context=integration_secret_context(integration.id),
        key_version=integration.secret_key_version,
    )


def get_org_integration(session: Session, org_id: uuid.UUID, integration_id: uuid.UUID) -> TicketIntegration | None:
    return session.scalars(
        select(TicketIntegration).where(
            TicketIntegration.id == integration_id,
            TicketIntegration.org_id == org_id,
        )
    ).one_or_none()


def integration_out(integration: TicketIntegration) -> dict[str, Any]:
    return {
        "id": integration.id,
        "name": integration.name,
        "provider": integration.provider,
        "description": integration.description,
        "config": dict(integration.config or {}),
        "is_enabled": integration.is_enabled,
        "created_at": integration.created_at.isoformat() if integration.created_at else None,
        "updated_at": integration.updated_at.isoformat() if integration.updated_at else None,
    }
