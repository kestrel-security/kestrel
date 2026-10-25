# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""GitHub live authentication: PAT and GitHub App installation tokens."""

from __future__ import annotations

import time

import httpx
import jwt
from kestrel.connectors.sdk.credentials import normalize_pem
from kestrel.connectors.sdk.transport import LiveHTTPTransport
from kestrel.security.ssrf import validate_connector_url

GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_ACCEPT = "application/vnd.github+json"


class GitHubAuthError(RuntimeError):
    """Invalid or incomplete GitHub auth secrets / App token minting failed."""


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": GITHUB_ACCEPT,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def build_pat_transport(secrets: dict[str, str]) -> LiveHTTPTransport:
    token = (secrets.get("token") or "").strip()
    if not token:
        raise GitHubAuthError("PAT auth requires secret field 'token'")
    return LiveHTTPTransport(base_url=GITHUB_API_BASE_URL, headers=_github_headers(token))


def _mint_github_app_installation_token(
    *,
    app_id: str,
    installation_id: str,
    private_key_pem: str,
) -> str:
    """Create a short-lived installation access token via the GitHub Apps API."""
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 9 * 60,
        "iss": app_id,
    }
    try:
        encoded = jwt.encode(payload, private_key_pem, algorithm="RS256")
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise GitHubAuthError(f"Could not sign GitHub App JWT (check private_key PEM): {exc}") from exc

    url = f"{GITHUB_API_BASE_URL}/app/installations/{installation_id}/access_tokens"
    # This call bypasses LiveHTTPTransport (it mints the credential the
    # transport will use), so it has to run the same SSRF check the transport
    # does -- otherwise a configurable base URL would have one unguarded path.
    validate_connector_url(url, field="github_app_token_url", require_https=True)
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                url,
                headers={
                    "Authorization": f"Bearer {encoded}",
                    "Accept": GITHUB_ACCEPT,
                    "X-GitHub-Api-Version": GITHUB_API_VERSION,
                },
            )
            response.raise_for_status()
            token = response.json().get("token")
            if not isinstance(token, str) or not token.strip():
                raise GitHubAuthError("GitHub App token response missing token")
            return token.strip()
    except GitHubAuthError:
        raise
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        raise GitHubAuthError(
            f"GitHub App installation token request failed ({exc.response.status_code}): {detail}"
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        # Transport failures, and a token response that is not JSON.
        raise GitHubAuthError(f"GitHub App installation token request failed: {exc}") from exc


def build_github_app_transport(secrets: dict[str, str]) -> LiveHTTPTransport:
    app_id = (secrets.get("app_id") or "").strip()
    installation_id = (secrets.get("installation_id") or "").strip()
    private_key = normalize_pem(secrets.get("private_key") or "")
    if not app_id or not installation_id or not private_key:
        raise GitHubAuthError("GitHub App auth requires secret fields 'app_id', 'installation_id', and 'private_key'")

    def mint() -> dict[str, str]:
        return _github_headers(
            _mint_github_app_installation_token(
                app_id=app_id,
                installation_id=installation_id,
                private_key_pem=private_key,
            )
        )

    # Installation tokens expire after an hour. A large org walk can outlive
    # that, so hand the transport a way to re-mint on 401 instead of failing
    # the run partway through the inventory.
    return LiveHTTPTransport(
        base_url=GITHUB_API_BASE_URL,
        headers=mint(),
        auth_refresh=mint,
    )


def build_fine_grained_pat_transport(secrets: dict[str, str]) -> LiveHTTPTransport:
    """Build a transport for a fine-grained PAT (beta token format ``github_pat_``).

    Fine-grained PATs have per-repository, per-permission scopes and cannot
    reach enterprise-level endpoints (``/enterprises/{slug}/...``) — those
    require a classic PAT with ``read:enterprise`` or a GitHub App with the
    enterprise-administration permission. Configure a classic PAT or GitHub App
    when enterprise-layer collection is required.
    """
    token = (secrets.get("token") or "").strip()
    if not token:
        raise GitHubAuthError("Fine-grained PAT auth requires secret field 'token'")
    return LiveHTTPTransport(base_url=GITHUB_API_BASE_URL, headers=_github_headers(token))


def build_live_transport(secrets: dict[str, str], *, auth_method: str | None = None) -> LiveHTTPTransport:
    """Build live transport from PAT, fine-grained PAT, or GitHub App secrets.

    When ``auth_method`` is omitted, chooses based on which secret fields are present
    (``token`` → PAT; App fields → github_app).
    """
    method = (auth_method or "").strip().lower()
    if not method:
        if (secrets.get("token") or "").strip():
            method = "pat"
        elif (secrets.get("app_id") or "").strip():
            method = "github_app"
        else:
            raise GitHubAuthError("Provide a PAT 'token' or GitHub App secrets (app_id, installation_id, private_key)")

    if method == "pat":
        return build_pat_transport(secrets)
    if method == "fine_grained_pat":
        return build_fine_grained_pat_transport(secrets)
    if method in {"github_app", "app"}:
        return build_github_app_transport(secrets)
    raise GitHubAuthError(f"Unsupported GitHub auth_method {auth_method!r}")
