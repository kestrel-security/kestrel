# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Live-mode auth for Google Workspace.

The Admin SDK requires a service account with domain-wide delegation
*impersonating* an admin user — the subject is part of the credential.
Live mode mints an OAuth2 access token via a signed JWT assertion
(``service_account_json`` + ``delegated_admin_email``).

An already-minted ``access_token`` secret remains supported for tests and
out-of-band minting.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt
from kestrel.connectors.sdk.credentials import bearer_headers, normalize_pem
from kestrel.connectors.sdk.transport import LiveHTTPTransport
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_url

GOOGLE_API_BASE_URL = "https://www.googleapis.com"
DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"

# Read-only scopes declared in manifest.yaml required_scopes. Kept in sync by
# `load_manifest_scopes()` and the unit test that asserts equality — minting a
# subset left domains / OUs / group settings / user tokens returning 403 on
# every live tenant.


def load_manifest_scopes() -> tuple[str, ...]:
    """Load ``required_scopes`` from this connector's ``manifest.yaml``."""
    from pathlib import Path

    import yaml

    manifest_path = Path(__file__).resolve().parents[2] / "manifest.yaml"
    data = yaml.safe_load(manifest_path.read_text())
    scopes = data.get("required_scopes") or []
    if not isinstance(scopes, list) or not scopes:
        raise RuntimeError(f"{manifest_path} has no required_scopes")
    return tuple(str(s) for s in scopes)


DEFAULT_SCOPES: tuple[str, ...] = load_manifest_scopes()

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class LiveAuthNotConfiguredError(RuntimeError):
    """Raised instead of silently falling back to an unauthenticated client,
    which would fail later with a confusing 401 from Google."""


class GoogleWorkspaceAuthError(LiveAuthNotConfiguredError):
    """Invalid service-account JSON, missing fields, or token exchange failure."""


def parse_service_account_json(raw: str) -> dict[str, Any]:
    """Parse and validate a Google Cloud service-account JSON key."""
    text = (raw or "").strip()
    if not text:
        raise GoogleWorkspaceAuthError("service_account_json is required")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GoogleWorkspaceAuthError(f"service_account_json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise GoogleWorkspaceAuthError("service_account_json must be a JSON object")

    sa_type = data.get("type")
    if sa_type is not None and sa_type != "service_account":
        raise GoogleWorkspaceAuthError(f"service_account_json type must be 'service_account' (got {sa_type!r})")

    client_email = data.get("client_email")
    private_key = data.get("private_key")
    if not isinstance(client_email, str) or not client_email.strip():
        raise GoogleWorkspaceAuthError("service_account_json missing client_email")
    if not isinstance(private_key, str) or not private_key.strip():
        raise GoogleWorkspaceAuthError("service_account_json missing private_key")

    token_uri = data.get("token_uri") or DEFAULT_TOKEN_URI
    if not isinstance(token_uri, str) or not token_uri.strip():
        raise GoogleWorkspaceAuthError("service_account_json has empty token_uri")
    token_uri = token_uri.strip()
    try:
        validate_connector_url(token_uri, field="token_uri", require_https=True)
    except UnsafeConnectorURLError as exc:
        raise GoogleWorkspaceAuthError(str(exc)) from exc
    # Prefer Google's token endpoint hosts only (SSRF already blocks private IPs).
    host = (urlparse(token_uri).hostname or "").lower()
    if host not in {"oauth2.googleapis.com", "www.googleapis.com", "accounts.google.com"}:
        raise GoogleWorkspaceAuthError(f"service_account_json token_uri host not allowed: {host!r}")

    return {
        "client_email": client_email.strip(),
        "private_key": normalize_pem(private_key),
        "token_uri": token_uri,
    }


def mint_access_token_from_service_account(
    *,
    service_account_json: str,
    delegated_admin_email: str,
    scopes: tuple[str, ...] | list[str] = DEFAULT_SCOPES,
    http_client: httpx.Client | None = None,
    now: int | None = None,
) -> str:
    """Sign a JWT assertion and exchange it for an OAuth2 access token."""
    subject = (delegated_admin_email or "").strip()
    if not subject or "@" not in subject:
        raise GoogleWorkspaceAuthError("delegated_admin_email must be a Workspace admin email to impersonate")
    if not scopes:
        raise GoogleWorkspaceAuthError("at least one OAuth scope is required")

    sa = parse_service_account_json(service_account_json)
    clock = int(time.time()) if now is None else now
    payload = {
        "iss": sa["client_email"],
        "sub": subject,
        "aud": sa["token_uri"],
        "iat": clock,
        "exp": clock + 3600,
        "scope": " ".join(scopes),
    }
    try:
        assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise GoogleWorkspaceAuthError(f"Could not sign service-account JWT (check private_key PEM): {exc}") from exc

    def _exchange(client: httpx.Client) -> str:
        response = client.post(
            sa["token_uri"],
            data={
                "grant_type": _JWT_BEARER_GRANT,
                "assertion": assertion,
            },
            headers={"Accept": "application/json"},
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:400] if exc.response is not None else str(exc)
            raise GoogleWorkspaceAuthError(f"Google token exchange failed ({exc.response.status_code}): {detail}") from exc
        body = response.json()
        token = body.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise GoogleWorkspaceAuthError("Google token response missing access_token")
        return token.strip()

    try:
        if http_client is not None:
            return _exchange(http_client)
        with httpx.Client(timeout=30.0) as client:
            return _exchange(client)
    except GoogleWorkspaceAuthError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        # Transport failures, and a token response that is not JSON.
        raise GoogleWorkspaceAuthError(f"Google token exchange failed: {exc}") from exc


def build_live_transport(secrets: dict[str, str]) -> LiveHTTPTransport:
    """Build a live transport from service-account secrets or a pre-minted token.

    Preference order:
    1. ``access_token`` (explicit / test path)
    2. ``service_account_json`` + ``delegated_admin_email``
    """
    access_token = (secrets.get("access_token") or "").strip()
    if access_token:
        return LiveHTTPTransport(
            base_url=GOOGLE_API_BASE_URL,
            headers=bearer_headers(access_token),
        )

    sa_json = secrets.get("service_account_json") or ""
    admin_email = secrets.get("delegated_admin_email") or ""
    if not (sa_json.strip() and admin_email.strip()):
        raise LiveAuthNotConfiguredError(
            "Live Google Workspace sync needs service_account_json and "
            "delegated_admin_email (or an already-minted access_token). "
            "Use sync_mode=fixtures for demos without credentials. "
            "See docs/connectors/google-workspace-setup.md."
        )

    def mint() -> dict[str, str]:
        token = mint_access_token_from_service_account(
            service_account_json=sa_json,
            delegated_admin_email=admin_email,
        )
        return {"Authorization": f"Bearer {token}"}

    # Google access tokens live for one hour. A large Workspace (or a slow
    # Drive walk) can outlast that, so the transport re-mints on the first 401
    # instead of failing the run halfway through the directory.
    return LiveHTTPTransport(
        base_url=GOOGLE_API_BASE_URL,
        headers={**mint(), "Accept": "application/json"},
        auth_refresh=mint,
    )
