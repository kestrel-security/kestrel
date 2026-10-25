# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Live-mode auth for Okta API.

Supports two auth methods:
- SSWS API token (legacy, legacy field name ``api_token``)
- OAuth 2.0 service app via ``private_key_jwt`` client authentication (recommended)

For OAuth, the connector uses the ``client_credentials`` grant with a signed
JWT assertion (``urn:ietf:params:oauth:client-assertion-type:jwt-bearer``).
The token is valid for 1 hour; ``LiveHTTPTransport`` re-mints on the first 401.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse, urlunparse

import httpx
import jwt
from kestrel.connectors.sdk.credentials import first_secret, normalize_pem
from kestrel.connectors.sdk.transport import LiveHTTPTransport
from kestrel.security.ssrf import UnsafeConnectorURLError, allowlisted_connector_hosts, validate_connector_url

# Admin Console hosts are ``{org}-admin.okta.com``; Management API is ``{org}.okta.com``.
_ADMIN_HOST = re.compile(
    r"^(?P<sub>.+)-admin\.(?P<zone>okta\.com|oktapreview\.com)$",
    re.IGNORECASE,
)

# Read-only OAuth scopes for the service-app auth method. Matches the
# ``required_scopes`` list on the manifest ``oauth`` auth_method entry.
OAUTH_SCOPES: tuple[str, ...] = (
    "okta.users.read",
    "okta.groups.read",
    "okta.apps.read",
    "okta.roles.read",
    "okta.policies.read",
    "okta.authenticators.read",
    "okta.logs.read",
    "okta.authorizationServers.read",
    "okta.orgs.read",
    "okta.behaviors.read",
    "okta.devices.read",
    "okta.logStreams.read",
    "okta.brands.read",
    "okta.domains.read",
    "okta.realms.read",
    "okta.apiTokens.read",
)

# Okta-operated domains an org URL may live under. The org URL decides where
# the SSWS token or OAuth assertion is sent, so an arbitrary host would let
# anyone who can edit the connector config collect the credential. A custom
# (vanity) Okta domain works only when the deployment operator lists it in
# KESTREL_CONNECTOR_URL_ALLOWLIST.
OKTA_DOMAINS: tuple[str, ...] = ("okta.com", "oktapreview.com", "okta-emea.com", "okta-gov.com", "okta.mil")

_JWT_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_JWT_LIFETIME_SECONDS = 300


class LiveAuthNotConfiguredError(RuntimeError):
    """Raised instead of silently falling back to an unauthenticated client."""


class OktaOAuthError(LiveAuthNotConfiguredError):
    """JWT signing or token-exchange failure for the service-app auth method."""


def normalize_okta_org_url(org_url: str) -> str:
    """Return an API-usable org base URL (no path, no Admin Console ``-admin`` host)."""
    cleaned = org_url.strip()
    parsed = urlparse(cleaned)
    host = parsed.hostname or ""
    match = _ADMIN_HOST.match(host)
    if match is not None:
        host = f"{match.group('sub')}.{match.group('zone')}"
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"
    scheme = parsed.scheme or "https"
    return urlunparse((scheme, netloc, "", "", "", ""))


def is_okta_host(host: str) -> bool:
    host = host.strip().rstrip(".").lower()
    return any(host == domain or host.endswith("." + domain) for domain in OKTA_DOMAINS)


def validate_okta_org_url(org_url: str) -> None:
    """Raise LiveAuthNotConfiguredError unless ``org_url`` is an https URL on
    an Okta-owned domain (or a host the deployment allowlists).

    Runs before any credential leaves the process. The generic SSRF check
    still applies afterwards.
    """
    parsed = urlparse(org_url)
    host = (parsed.hostname or "").lower()
    if host and host in allowlisted_connector_hosts():
        return
    if parsed.scheme != "https":
        raise LiveAuthNotConfiguredError("org_url must use https (for example https://acme.okta.com)")
    if not is_okta_host(host):
        raise LiveAuthNotConfiguredError(
            f"org_url host {host or '(none)'!r} is not an Okta domain "
            f"({', '.join('*.' + d for d in OKTA_DOMAINS)}). To use a custom Okta domain, "
            "add its hostname to KESTREL_CONNECTOR_URL_ALLOWLIST."
        )


def mint_oauth_token(
    *,
    org_url: str,
    client_id: str,
    private_key_pem: str,
    scopes: tuple[str, ...] = OAUTH_SCOPES,
    http_client: httpx.Client | None = None,
    now: int | None = None,
) -> str:
    """Sign a private_key_jwt assertion and exchange it at Okta's token endpoint.

    ``org_url`` must already be normalized (no ``-admin`` host).
    """
    token_endpoint = f"{org_url.rstrip('/')}/oauth2/v1/token"
    clock = int(time.time()) if now is None else now
    pem = normalize_pem(private_key_pem)
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": clock,
        "exp": clock + _JWT_LIFETIME_SECONDS,
    }
    try:
        assertion = jwt.encode(payload, pem, algorithm="RS256")
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise OktaOAuthError(f"Could not sign Okta JWT (check private_key_pem PEM): {exc}") from exc

    def _exchange(client: httpx.Client) -> str:
        resp = client.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": _JWT_CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
                "scope": " ".join(scopes),
            },
            headers={"Accept": "application/json"},
        )
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:400] if exc.response is not None else str(exc)
            raise OktaOAuthError(f"Okta token exchange failed ({exc.response.status_code}): {detail}") from exc
        body = resp.json()
        token = body.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise OktaOAuthError("Okta token response missing access_token")
        return token.strip()

    try:
        if http_client is not None:
            return _exchange(http_client)
        with httpx.Client(timeout=30.0) as client:
            return _exchange(client)
    except OktaOAuthError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        # Transport failures, and a token response that is not JSON.
        raise OktaOAuthError(f"Okta token exchange failed: {exc}") from exc


def build_live_transport(org_url: str, secrets: dict[str, str]) -> LiveHTTPTransport:
    """Build a live transport from secrets.

    Preference order:
    1. ``client_id`` + ``private_key_pem``  → OAuth 2.0 service-app (recommended)
    2. ``api_token`` / ``token`` / ``ssws_token`` → SSWS API token (legacy)
    """
    org_url = normalize_okta_org_url(org_url)
    validate_okta_org_url(org_url)
    try:
        validate_connector_url(org_url, field="org_url", require_https=True)
    except UnsafeConnectorURLError as exc:
        raise LiveAuthNotConfiguredError(str(exc)) from exc

    client_id = (secrets.get("client_id") or "").strip()
    private_key_pem = (secrets.get("private_key_pem") or "").strip()

    if client_id and private_key_pem:
        return _build_oauth_transport(org_url, client_id, private_key_pem)

    token = first_secret(secrets, "api_token", "token", "ssws_token")
    if token:
        return LiveHTTPTransport(
            base_url=org_url,
            headers={
                "Authorization": f"SSWS {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    raise LiveAuthNotConfiguredError(
        "Live Okta sync needs either (a) client_id + private_key_pem for OAuth 2.0 "
        "service-app auth, or (b) an api_token for SSWS auth. "
        "Use sync_mode=fixtures for offline demos. See docs/connectors/okta-setup.md."
    )


def _build_oauth_transport(org_url: str, client_id: str, private_key_pem: str) -> LiveHTTPTransport:
    """OAuth 2.0 Bearer transport with automatic token re-mint on 401."""

    def mint() -> dict[str, str]:
        token = mint_oauth_token(org_url=org_url, client_id=client_id, private_key_pem=private_key_pem)
        return {"Authorization": f"Bearer {token}"}

    return LiveHTTPTransport(
        base_url=org_url,
        headers={**mint(), "Accept": "application/json", "Content-Type": "application/json"},
        auth_refresh=mint,
    )
