# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org LLM settings authoring + credential resolution for policy AI."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.llm_settings import (
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    LLM_PROVIDERS,
    PROVIDER_ANTHROPIC,
    PROVIDER_OPENAI,
    OrgLlmSettings,
)
from kestrel.env import getenv_str
from kestrel.secrets.crypto import (
    EnvKeyProvider,
    KeyProvider,
    MissingMasterKeyError,
    decrypt_secret,
    encrypt_secret,
    secret_context,
)
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_url

DEFAULT_LLM_BASE_URL = DEFAULT_BASE_URLS[PROVIDER_OPENAI]
DEFAULT_LLM_MODEL = DEFAULT_MODELS[PROVIDER_OPENAI]


class LlmSettingsError(ValueError):
    """Invalid LLM settings input."""


@dataclass(frozen=True)
class LlmCredentials:
    """Resolved credentials for a chat completion call."""

    api_key: str
    provider: str
    model: str
    base_url: str
    source: str  # "org" | "env"


def validate_provider(provider: str) -> str:
    cleaned = provider.strip().lower()
    if cleaned not in LLM_PROVIDERS:
        raise LlmSettingsError(f"unsupported provider {provider!r}; supported: {', '.join(sorted(LLM_PROVIDERS))}")
    return cleaned


def validate_model(model: str) -> str:
    cleaned = model.strip()
    if not cleaned or len(cleaned) > 128:
        raise LlmSettingsError("model must be 1–128 characters")
    return cleaned


def validate_api_key(api_key: str) -> str:
    cleaned = api_key.strip()
    if len(cleaned) < 8:
        raise LlmSettingsError("api_key must be at least 8 characters")
    if len(cleaned) > 4096:
        raise LlmSettingsError("api_key is too long")
    return cleaned


def normalize_base_url(provider: str, base_url: str | None) -> str | None:
    if base_url is None or not str(base_url).strip():
        return None
    cleaned = str(base_url).strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LlmSettingsError("base_url must be an http(s) URL")
    try:
        validate_connector_url(cleaned, field="base_url", require_https=True)
    except UnsafeConnectorURLError as exc:
        raise LlmSettingsError(str(exc)) from exc
    return cleaned


def llm_secret_context(row_id: uuid.UUID) -> bytes:
    """Associated data binding an LLM API key to its settings row."""
    return secret_context(OrgLlmSettings.__tablename__, row_id, "secret")


def get_org_llm_settings(session: Session, org_id: uuid.UUID) -> OrgLlmSettings | None:
    return session.scalar(select(OrgLlmSettings).where(OrgLlmSettings.org_id == org_id))


def settings_out(row: OrgLlmSettings | None) -> dict[str, Any]:
    """Status-only payload — never ciphertext or plaintext."""
    if row is None:
        return {
            "configured": False,
            "provider": None,
            "model": None,
            "base_url": None,
            "is_enabled": False,
            "api_key_configured": False,
            "defaults": {
                "providers": sorted(LLM_PROVIDERS),
                "models": dict(DEFAULT_MODELS),
                "base_urls": dict(DEFAULT_BASE_URLS),
            },
        }
    return {
        "configured": True,
        "provider": row.provider,
        "model": row.model,
        "base_url": row.base_url,
        "is_enabled": row.is_enabled,
        "api_key_configured": True,
        "defaults": {
            "providers": sorted(LLM_PROVIDERS),
            "models": dict(DEFAULT_MODELS),
            "base_urls": dict(DEFAULT_BASE_URLS),
        },
    }


def upsert_org_llm_settings(
    session: Session,
    *,
    org_id: uuid.UUID,
    provider: str,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    is_enabled: bool = True,
    key_provider: KeyProvider | None = None,
) -> OrgLlmSettings:
    """Create or update org LLM settings.

    ``api_key`` is required on create; on update, omit/blank to keep the
    existing key -- unless the provider or base_url changes the endpoint the
    key would be sent to, in which case it must be re-entered.
    """
    provider_id = validate_provider(provider)
    model_id = validate_model(model) if model else DEFAULT_MODELS[provider_id]
    normalized_base = normalize_base_url(provider_id, base_url)
    kp = key_provider or EnvKeyProvider()

    row = get_org_llm_settings(session, org_id)
    if row is None:
        if not api_key or not api_key.strip():
            raise LlmSettingsError("api_key is required when configuring AI for the first time")
        token = validate_api_key(api_key)
        row_id = uuid.uuid4()
        encrypted = encrypt_secret(kp, org_id, token, context=llm_secret_context(row_id))
        row = OrgLlmSettings(
            id=row_id,
            org_id=org_id,
            provider=provider_id,
            model=model_id,
            base_url=normalized_base,
            secret_ciphertext=encrypted.ciphertext,
            secret_nonce=encrypted.nonce,
            secret_key_version=encrypted.key_version,
            is_enabled=is_enabled,
        )
        session.add(row)
        return row

    # The stored key never follows the settings to a new endpoint. Switching
    # provider changes the default endpoint too, so compare effective URLs.
    old_endpoint = (row.base_url or DEFAULT_BASE_URLS.get(row.provider, DEFAULT_LLM_BASE_URL)).rstrip("/").lower()
    new_endpoint = (normalized_base or DEFAULT_BASE_URLS.get(provider_id, DEFAULT_LLM_BASE_URL)).rstrip("/").lower()
    if old_endpoint != new_endpoint and not (api_key and api_key.strip()):
        raise LlmSettingsError(
            "api_key is required when changing provider or base_url (the stored key is not sent to a new endpoint)"
        )

    row.provider = provider_id
    row.model = model_id
    row.base_url = normalized_base
    row.is_enabled = is_enabled
    if api_key is not None and api_key.strip():
        token = validate_api_key(api_key)
        encrypted = encrypt_secret(kp, org_id, token, context=llm_secret_context(row.id))
        row.secret_ciphertext = encrypted.ciphertext
        row.secret_nonce = encrypted.nonce
        row.secret_key_version = encrypted.key_version
    return row


def clear_org_llm_settings(session: Session, org_id: uuid.UUID) -> bool:
    row = get_org_llm_settings(session, org_id)
    if row is None:
        return False
    session.delete(row)
    return True


def resolve_llm_credentials(
    session: Session | None,
    org_id: uuid.UUID | None,
    *,
    key_provider: KeyProvider | None = None,
) -> LlmCredentials | None:
    """Prefer enabled org settings; fall back to ``KESTREL_LLM_*`` env. None → stub path."""
    if session is not None and org_id is not None:
        row = get_org_llm_settings(session, org_id)
        if row is not None and row.is_enabled:
            try:
                kp = key_provider or EnvKeyProvider()
                api_key = decrypt_secret(
                    kp,
                    org_id,
                    row.secret_ciphertext,
                    row.secret_nonce,
                    context=llm_secret_context(row.id),
                    key_version=row.secret_key_version,
                )
            except MissingMasterKeyError:
                pass
            else:
                base = (row.base_url or DEFAULT_BASE_URLS.get(row.provider, DEFAULT_LLM_BASE_URL)).rstrip("/")
                return LlmCredentials(
                    api_key=api_key,
                    provider=row.provider,
                    model=row.model,
                    base_url=base,
                    source="org",
                )

    api_key = getenv_str("KESTREL_LLM_API_KEY").strip()
    if not api_key:
        return None
    provider = getenv_str("KESTREL_LLM_PROVIDER", PROVIDER_OPENAI).strip().lower() or PROVIDER_OPENAI
    if provider not in LLM_PROVIDERS:
        provider = PROVIDER_OPENAI
    base_url = getenv_str("KESTREL_LLM_BASE_URL", DEFAULT_BASE_URLS[provider]).rstrip("/")
    model = getenv_str("KESTREL_LLM_MODEL", DEFAULT_MODELS[provider])
    return LlmCredentials(
        api_key=api_key,
        provider=provider,
        model=model,
        base_url=base_url,
        source="env",
    )


__all__ = [
    "DEFAULT_LLM_BASE_URL",
    "DEFAULT_LLM_MODEL",
    "PROVIDER_ANTHROPIC",
    "PROVIDER_OPENAI",
    "LlmCredentials",
    "LlmSettingsError",
    "clear_org_llm_settings",
    "get_org_llm_settings",
    "normalize_base_url",
    "resolve_llm_credentials",
    "settings_out",
    "upsert_org_llm_settings",
    "validate_api_key",
    "validate_model",
    "validate_provider",
]
