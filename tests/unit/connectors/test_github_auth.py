# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for GitHub live authentication.

`auth.py` had no coverage at all: JWT signing, PEM newline normalization, auth
method inference, installation-token minting, and every GitHubAuthError branch
were unexercised. Nothing here touches the network -- the minting call is
driven through an injected httpx MockTransport.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from kestrel_connector_github import auth as gh_auth
from kestrel_connector_github.auth import (
    GitHubAuthError,
    build_live_transport,
    build_pat_transport,
)


@pytest.fixture(scope="module")
def private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture(autouse=True)
def _skip_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """LiveHTTPTransport and GitHub App minting validate URLs via DNS; unit tests must not."""
    monkeypatch.setattr("kestrel.connectors.sdk.transport.validate_connector_url", lambda *a, **k: None)
    monkeypatch.setattr("kestrel_connector_github.auth.validate_connector_url", lambda *a, **k: None)
    monkeypatch.setattr("kestrel.security.ssrf.validate_connector_url", lambda *a, **k: None)


def _app_secrets(pem: str) -> dict[str, str]:
    return {"app_id": "12345", "installation_id": "67890", "private_key": pem}


@pytest.fixture
def minting(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture installation-token mints, returning a fresh token each time."""
    calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append({"url": str(request.url), "auth": request.headers.get("Authorization")})
        return httpx.Response(200, content=json.dumps({"token": f"ghs_token_{len(calls)}"}))

    real_client = httpx.Client

    def fake_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gh_auth.httpx, "Client", fake_client)
    return calls


def test_pat_transport_sets_bearer_and_api_version_headers() -> None:
    transport = build_pat_transport({"token": "ghp_secret"})
    assert transport.client.headers["Authorization"] == "Bearer ghp_secret"
    assert transport.client.headers["X-GitHub-Api-Version"] == gh_auth.GITHUB_API_VERSION
    assert transport.client.headers["Accept"] == gh_auth.GITHUB_ACCEPT


def test_pat_transport_rejects_a_blank_token() -> None:
    with pytest.raises(GitHubAuthError, match="requires secret field 'token'"):
        build_pat_transport({"token": "   "})


def test_app_transport_mints_a_token_and_uses_it(private_key_pem: str, minting: list) -> None:
    transport = gh_auth.build_github_app_transport(_app_secrets(private_key_pem))
    assert len(minting) == 1
    assert minting[0]["url"].endswith("/app/installations/67890/access_tokens")
    assert transport.client.headers["Authorization"] == "Bearer ghs_token_1"


@pytest.fixture
def stub_mint(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub token minting itself, leaving `httpx.Client` real.

    The `minting` fixture patches `httpx.Client` module-wide, which would also
    capture the API client these tests install -- so refresh behaviour is
    tested against a stubbed mint instead.
    """
    minted: list[str] = []

    def fake_mint(*, app_id: str, installation_id: str, private_key_pem: str) -> str:
        minted.append(f"ghs_token_{len(minted) + 1}")
        return minted[-1]

    monkeypatch.setattr(gh_auth, "_mint_github_app_installation_token", fake_mint)
    return minted


def _with_api(transport: Any, handler: Any) -> Any:
    """Point an already-built transport at a canned API, keeping its headers."""
    transport.client = httpx.Client(
        base_url=str(transport.client.base_url),
        headers=transport.client.headers,
        transport=httpx.MockTransport(handler),
    )
    return transport


def test_app_transport_refreshes_the_token_on_401(private_key_pem: str, stub_mint: list[str]) -> None:
    # Installation tokens expire after an hour; a long org walk must recover
    # rather than failing partway through the inventory.
    responses = {"n": 0}

    def api(request: httpx.Request) -> httpx.Response:
        responses["n"] += 1
        if responses["n"] == 1:
            return httpx.Response(401, content=json.dumps({"message": "Bad credentials"}))
        return httpx.Response(
            200,
            content=json.dumps({"ok": True, "seen": request.headers.get("Authorization")}),
        )

    transport = _with_api(gh_auth.build_github_app_transport(_app_secrets(private_key_pem)), api)
    result = transport.request("GET", "/orgs/acme")
    assert result["ok"] is True
    assert result["seen"] == "Bearer ghs_token_2"
    assert stub_mint == ["ghs_token_1", "ghs_token_2"]


def test_the_token_is_refreshed_at_most_once_per_request(private_key_pem: str, stub_mint: list[str]) -> None:
    # A credential that is genuinely revoked must not spin minting forever.
    transport = _with_api(
        gh_auth.build_github_app_transport(_app_secrets(private_key_pem)),
        lambda request: httpx.Response(401, content=b"{}"),
    )
    with pytest.raises(httpx.HTTPStatusError):
        transport.request("GET", "/orgs/acme")
    assert stub_mint == ["ghs_token_1", "ghs_token_2"]


def test_a_failed_refresh_surfaces_the_original_401(private_key_pem: str, stub_mint: list[str]) -> None:
    def explode() -> dict[str, str]:
        raise GitHubAuthError("mint failed")

    transport = _with_api(
        gh_auth.build_github_app_transport(_app_secrets(private_key_pem)),
        lambda request: httpx.Response(401, content=b"{}"),
    )
    transport._auth_refresh = explode
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        transport.request("GET", "/orgs/acme")
    assert excinfo.value.response.status_code == 401


def test_a_pat_transport_has_no_refresh_hook(private_key_pem: str) -> None:
    # PATs do not expire on a schedule; re-minting is meaningless for them.
    assert build_pat_transport({"token": "ghp_x"})._auth_refresh is None


def test_app_transport_normalizes_escaped_newlines_in_a_pasted_pem(private_key_pem: str, minting: list) -> None:
    # Textarea paste turns real newlines into a literal backslash-n.
    escaped = private_key_pem.replace("\n", "\\n")
    gh_auth.build_github_app_transport(_app_secrets(escaped))
    assert len(minting) == 1


def test_app_transport_requires_all_three_secret_fields(private_key_pem: str) -> None:
    with pytest.raises(GitHubAuthError, match="app_id"):
        gh_auth.build_github_app_transport({"app_id": "1", "installation_id": "2"})


def test_an_unsignable_private_key_is_reported_as_an_auth_error() -> None:
    with pytest.raises(GitHubAuthError, match="Could not sign GitHub App JWT"):
        gh_auth.build_github_app_transport(_app_secrets("not-a-pem"))


def test_a_token_response_without_a_token_is_an_auth_error(private_key_pem: str, monkeypatch: pytest.MonkeyPatch) -> None:
    real_client = httpx.Client

    def fake_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(200, content=json.dumps({"expires_at": "soon"}))
        )
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gh_auth.httpx, "Client", fake_client)
    with pytest.raises(GitHubAuthError, match="missing token"):
        gh_auth.build_github_app_transport(_app_secrets(private_key_pem))


def test_a_minting_http_error_is_reported_with_its_status(private_key_pem: str, monkeypatch: pytest.MonkeyPatch) -> None:
    real_client = httpx.Client

    def fake_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(404, content=b'{"message":"Not Found"}'))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gh_auth.httpx, "Client", fake_client)
    with pytest.raises(GitHubAuthError, match="failed \\(404\\)"):
        gh_auth.build_github_app_transport(_app_secrets(private_key_pem))


def test_auth_method_is_inferred_from_the_secret_fields_present(private_key_pem: str, minting: list) -> None:
    assert build_live_transport({"token": "ghp_x"}).client.headers["Authorization"] == "Bearer ghp_x"
    app = build_live_transport(_app_secrets(private_key_pem))
    assert app.client.headers["Authorization"] == "Bearer ghs_token_1"


def test_an_explicit_auth_method_overrides_inference(private_key_pem: str, minting: list) -> None:
    secrets = {**_app_secrets(private_key_pem), "token": "ghp_ignored"}
    transport = build_live_transport(secrets, auth_method="github_app")
    assert transport.client.headers["Authorization"] == "Bearer ghs_token_1"


@pytest.mark.parametrize("alias", ["github_app", "app", "GitHub_App", " app "])
def test_github_app_aliases_are_accepted(alias: str, private_key_pem: str, minting: list) -> None:
    build_live_transport(_app_secrets(private_key_pem), auth_method=alias)


def test_no_usable_secrets_is_an_auth_error() -> None:
    with pytest.raises(GitHubAuthError, match="Provide a PAT 'token' or GitHub App secrets"):
        build_live_transport({})


def test_an_unknown_auth_method_is_rejected() -> None:
    with pytest.raises(GitHubAuthError, match="Unsupported GitHub auth_method"):
        build_live_transport({"token": "ghp_x"}, auth_method="oauth")
