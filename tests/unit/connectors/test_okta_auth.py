# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Okta OAuth 2.0 service-app auth (private_key_jwt).

Tests use a mock httpx client so no real Okta tenant is needed.
Key requirements:
- The JWT assertion is RS256-signed with the provided PEM.
- The token endpoint is ``{org_url}/oauth2/v1/token``.
- A 4xx from the token endpoint raises OktaOAuthError.
- The transport falls back to SSWS when client_id is absent.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from kestrel_connector_okta.auth import (
    LiveAuthNotConfiguredError,
    OktaOAuthError,
    build_live_transport,
    mint_oauth_token,
    normalize_okta_org_url,
    validate_okta_org_url,
)

ORG_URL = "https://acme.okta.com"


def _generate_rsa_pem() -> str:
    """Generate a minimal RSA-2048 key for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


_RSA_PEM = _generate_rsa_pem()
_CLIENT_ID = "0oa_test_client_id"
_TOKEN_ENDPOINT = f"{ORG_URL}/oauth2/v1/token"


def _mock_http_client(status: int = 200, body: dict[str, Any] | None = None) -> httpx.Client:
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = status
    mock_response.text = json.dumps(body or {})
    if status >= 400:
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status}",
            request=httpx.Request("POST", _TOKEN_ENDPOINT),
            response=mock_response,
        )
    else:
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = body or {}

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_response
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


def test_mint_oauth_token_sends_client_credentials_grant() -> None:
    client = _mock_http_client(200, {"access_token": "tok-abc123", "token_type": "Bearer"})
    token = mint_oauth_token(
        org_url=ORG_URL,
        client_id=_CLIENT_ID,
        private_key_pem=_RSA_PEM,
        http_client=client,
    )
    assert token == "tok-abc123"
    call_kwargs = client.post.call_args
    assert call_kwargs[0][0] == _TOKEN_ENDPOINT
    data = call_kwargs[1]["data"]
    assert data["grant_type"] == "client_credentials"
    assert "client_assertion" in data
    assert data["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert "okta.users.read" in data["scope"]


def test_mint_oauth_token_raises_on_401() -> None:
    client = _mock_http_client(401, {"error": "unauthorized_client"})
    with pytest.raises(OktaOAuthError, match="Okta token exchange failed"):
        mint_oauth_token(
            org_url=ORG_URL,
            client_id=_CLIENT_ID,
            private_key_pem=_RSA_PEM,
            http_client=client,
        )


def test_mint_oauth_token_raises_on_missing_access_token() -> None:
    client = _mock_http_client(200, {"token_type": "Bearer"})
    with pytest.raises(OktaOAuthError, match="missing access_token"):
        mint_oauth_token(
            org_url=ORG_URL,
            client_id=_CLIENT_ID,
            private_key_pem=_RSA_PEM,
            http_client=client,
        )


def test_mint_oauth_token_raises_on_bad_pem() -> None:
    with pytest.raises(OktaOAuthError, match="Could not sign"):
        mint_oauth_token(
            org_url=ORG_URL,
            client_id=_CLIENT_ID,
            private_key_pem="not-a-pem",
            http_client=_mock_http_client(200, {"access_token": "tok"}),
        )


def test_build_live_transport_prefers_oauth_when_client_id_present() -> None:
    client = _mock_http_client(200, {"access_token": "bearer-token", "token_type": "Bearer"})
    with (
        patch("kestrel_connector_okta.auth.httpx.Client", return_value=client),
        patch("kestrel_connector_okta.auth.validate_connector_url"),
        patch("kestrel.connectors.sdk.transport.validate_connector_url"),
    ):
        build_live_transport(
            ORG_URL,
            {"client_id": _CLIENT_ID, "private_key_pem": _RSA_PEM},
        )
    # The transport posts to the token endpoint (OAuth path was taken)
    assert client.post.called
    call_url = client.post.call_args[0][0]
    assert "/oauth2/v1/token" in call_url


def test_build_live_transport_uses_ssws_when_no_oauth_secrets() -> None:
    from kestrel.connectors.sdk.transport import LiveHTTPTransport

    with (
        patch("kestrel_connector_okta.auth.validate_connector_url"),
        patch("kestrel.connectors.sdk.transport.validate_connector_url"),
    ):
        transport = build_live_transport(ORG_URL, {"api_token": "ssws-tok"})
    assert isinstance(transport, LiveHTTPTransport)


def test_build_live_transport_raises_when_no_secrets_provided() -> None:
    with (
        patch("kestrel_connector_okta.auth.validate_connector_url"),
        patch("kestrel.connectors.sdk.transport.validate_connector_url"),
        pytest.raises(LiveAuthNotConfiguredError),
    ):
        build_live_transport(ORG_URL, {})


@pytest.mark.parametrize(
    "org_url",
    ["https://acme.okta.com", "https://acme.oktapreview.com", "https://acme.okta-emea.com", "https://x.okta-gov.com"],
)
def test_okta_owned_org_urls_are_accepted(org_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    validate_okta_org_url(org_url)  # must not raise


@pytest.mark.parametrize(
    "org_url",
    [
        "https://attacker.example",
        "https://okta.com.attacker.example",
        "https://attackerokta.com",
        "http://acme.okta.com",  # https only
    ],
)
def test_non_okta_org_urls_never_receive_the_token(org_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The credential-exfiltration regression: a changed org_url must fail
    before any request is built, so the SSWS token never leaves."""
    monkeypatch.delenv("KESTREL_CONNECTOR_URL_ALLOWLIST", raising=False)
    sent: list[str] = []
    with (
        patch("kestrel_connector_okta.auth.LiveHTTPTransport", side_effect=lambda **kw: sent.append(kw["base_url"])),
        pytest.raises(LiveAuthNotConfiguredError),
    ):
        build_live_transport(org_url, {"api_token": "ssws-tok"})
    assert sent == []


def test_custom_okta_domain_works_when_allowlisted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KESTREL_CONNECTOR_URL_ALLOWLIST", "login.acme.example")
    validate_okta_org_url("https://login.acme.example")  # must not raise


def test_normalize_okta_org_url_strips_admin_host() -> None:
    assert normalize_okta_org_url("https://acme-admin.okta.com") == "https://acme.okta.com"
    assert normalize_okta_org_url("https://acme.okta.com") == "https://acme.okta.com"
    assert normalize_okta_org_url("  https://acme.okta.com/  ") == "https://acme.okta.com"
