# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Create/update helpers for webhook endpoints (shared by the API router)."""

from __future__ import annotations

import re
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.webhook import SUPPORTED_WEBHOOK_EVENTS, WebhookEndpoint
from kestrel.secrets.crypto import EnvKeyProvider, KeyProvider, decrypt_secret, encrypt_secret, secret_context
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_url

_SECRET_PREFIX = "whsec_"
_NAME_RE = re.compile(r"^[\w .'/:-]{1,120}$")


class WebhookAuthoringError(ValueError):
    """Invalid webhook endpoint input (URL, events, name, …)."""


def generate_signing_secret() -> str:
    return _SECRET_PREFIX + secrets.token_urlsafe(32)


def normalize_events(events: list[str]) -> list[str]:
    if not events:
        raise WebhookAuthoringError("events must include at least one event type")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in events:
        event = raw.strip()
        if event not in SUPPORTED_WEBHOOK_EVENTS:
            raise WebhookAuthoringError(
                f"unsupported event type {event!r}; supported: {', '.join(sorted(SUPPORTED_WEBHOOK_EVENTS))}"
            )
        if event not in seen:
            seen.add(event)
            normalized.append(event)
    return normalized


def validate_endpoint_url(url: str) -> str:
    """Endpoint URLs must be https: every delivery carries an HMAC-signed
    payload. Plain http is accepted only for hosts on
    ``KESTREL_CONNECTOR_URL_ALLOWLIST`` (local labs), mirroring the
    credentialed-connector rule."""
    cleaned = url.strip()
    if not cleaned:
        raise WebhookAuthoringError("url is required")
    try:
        validate_connector_url(cleaned, field="url", require_https=True)
    except UnsafeConnectorURLError as exc:
        raise WebhookAuthoringError(str(exc)) from exc
    return cleaned


def validate_name(name: str) -> str:
    cleaned = name.strip()
    if not _NAME_RE.match(cleaned):
        raise WebhookAuthoringError("name must be 1–120 characters (letters, digits, spaces, and ._'/: -)")
    return cleaned


def endpoint_secret_context(endpoint_id: uuid.UUID) -> bytes:
    """Associated data binding a signing secret to its endpoint row."""
    return secret_context(WebhookEndpoint.__tablename__, endpoint_id, "secret")


def create_endpoint(
    session: Session,
    *,
    org_id: uuid.UUID,
    name: str,
    url: str,
    events: list[str],
    description: str | None = None,
    key_provider: KeyProvider | None = None,
) -> tuple[WebhookEndpoint, str]:
    """Creates an endpoint and returns ``(row, plaintext_signing_secret)``.
    The plaintext secret is never persisted; callers must surface it once.
    """
    provider = key_provider or EnvKeyProvider()
    secret = generate_signing_secret()
    endpoint_id = uuid.uuid4()
    encrypted = encrypt_secret(provider, org_id, secret, context=endpoint_secret_context(endpoint_id))

    endpoint = WebhookEndpoint(
        id=endpoint_id,
        org_id=org_id,
        name=validate_name(name),
        url=validate_endpoint_url(url),
        description=description.strip() if description else None,
        events=normalize_events(events),
        secret_ciphertext=encrypted.ciphertext,
        secret_nonce=encrypted.nonce,
        secret_key_version=encrypted.key_version,
        is_enabled=True,
    )
    session.add(endpoint)
    session.flush()
    return endpoint, secret


def update_endpoint(
    session: Session,
    endpoint: WebhookEndpoint,
    *,
    name: str | None = None,
    url: str | None = None,
    events: list[str] | None = None,
    description: str | None = None,
    is_enabled: bool | None = None,
    description_set: bool = False,
) -> WebhookEndpoint:
    if name is not None:
        endpoint.name = validate_name(name)
    if url is not None:
        endpoint.url = validate_endpoint_url(url)
    if events is not None:
        endpoint.events = normalize_events(events)
    if description_set:
        endpoint.description = description.strip() if description else None
    if is_enabled is not None:
        endpoint.is_enabled = is_enabled
    session.flush()
    return endpoint


def rotate_secret(
    session: Session,
    endpoint: WebhookEndpoint,
    *,
    key_provider: KeyProvider | None = None,
) -> str:
    provider = key_provider or EnvKeyProvider()
    secret = generate_signing_secret()
    encrypted = encrypt_secret(provider, endpoint.org_id, secret, context=endpoint_secret_context(endpoint.id))
    endpoint.secret_ciphertext = encrypted.ciphertext
    endpoint.secret_nonce = encrypted.nonce
    endpoint.secret_key_version = encrypted.key_version
    session.flush()
    return secret


def decrypt_endpoint_secret(
    endpoint: WebhookEndpoint,
    *,
    key_provider: KeyProvider | None = None,
) -> str:
    provider = key_provider or EnvKeyProvider()
    return decrypt_secret(
        provider,
        endpoint.org_id,
        endpoint.secret_ciphertext,
        endpoint.secret_nonce,
        context=endpoint_secret_context(endpoint.id),
        key_version=endpoint.secret_key_version,
    )


def get_org_endpoint(session: Session, org_id: uuid.UUID, endpoint_id: uuid.UUID) -> WebhookEndpoint | None:
    return session.scalars(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == endpoint_id,
            WebhookEndpoint.org_id == org_id,
        )
    ).one_or_none()
