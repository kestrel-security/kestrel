# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Google Workspace error classification, service-account auth, and health.

Exercised through the connector's public surface (`check_health`,
`classify_gws_failure`, `parse_service_account_json`,
`mint_access_token_from_service_account`, `build_live_transport`). The token
exchange goes to an `httpx.MockTransport`, DNS is faked, and the JWT clock is
pinned with `now=`; nothing touches the network.
"""

from __future__ import annotations

import json
import socket
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from kestrel_connector_google_workspace.auth import (
    DEFAULT_TOKEN_URI,
    GOOGLE_API_BASE_URL,
    GoogleWorkspaceAuthError,
    LiveAuthNotConfiguredError,
    build_live_transport,
    mint_access_token_from_service_account,
    parse_service_account_json,
)
from kestrel_connector_google_workspace.client import GoogleWorkspaceClient
from kestrel_connector_google_workspace.health import check_health, classify_gws_failure
from kestrel_connector_google_workspace.http import is_rate_limit, is_skippable


def _http_error(status: int, message: str = "boom") -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://admin.googleapis.com/admin/directory/v1/users")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError(message, request=request, response=response)


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every host to a public address so URL validation never hits DNS."""

    def fake_getaddrinfo(host: str, *args: Any, **kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.80.46", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _sa_json(key: rsa.RSAPrivateKey, **overrides: Any) -> str:
    data: dict[str, Any] = {
        "type": "service_account",
        "client_email": "kestrel@acme-project.iam.gserviceaccount.com",
        "private_key": _pem(key),
        "token_uri": DEFAULT_TOKEN_URI,
    }
    data.update(overrides)
    return json.dumps({k: v for k, v in data.items() if v is not None})


# -- classification ------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [_http_error(429), _http_error(403, "rateLimitExceeded"), _http_error(403, "User Rate Limit Exceeded")],
)
def test_rate_limits_are_classified_before_permission(exc: BaseException) -> None:
    assert classify_gws_failure(exc) == "rate_limit"


@pytest.mark.parametrize(
    "exc",
    [_http_error(401), _http_error(403, "invalid_grant: bad subject"), _http_error(403, "Unauthorized client")],
)
def test_bad_credentials_are_authentication(exc: BaseException) -> None:
    assert classify_gws_failure(exc) == "authentication"


def test_a_plain_403_is_permission() -> None:
    assert classify_gws_failure(_http_error(403, "Not Authorized to access this resource/api")) == "permission"


def _google_error(status: int, *reasons: str, api_status: str | None = None) -> httpx.HTTPStatusError:
    """A real Google error: the message is httpx's, the reason is in the body only."""
    body: dict[str, Any] = {
        "error": {
            "code": status,
            "message": "Quota exceeded for quota metric 'Queries'",
            "errors": [{"domain": "usageLimits", "reason": reason, "message": "x"} for reason in reasons],
        }
    }
    if api_status:
        body["error"]["status"] = api_status
    request = httpx.Request("GET", "https://admin.googleapis.com/admin/directory/v1/users")
    response = httpx.Response(status, json=body, request=request)
    return httpx.HTTPStatusError(f"Client error '{status} Forbidden' for url", request=request, response=response)


@pytest.mark.parametrize("reason", ["rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"])
def test_a_quota_403_is_read_from_the_body_not_the_message(reason: str) -> None:
    exc = _google_error(403, reason)
    assert is_rate_limit(exc)
    assert classify_gws_failure(exc) == "rate_limit"
    # Never skippable: dropping a family because the token was throttled would
    # report an incomplete inventory as complete.
    assert not is_skippable(exc)


def test_a_resource_exhausted_status_is_a_rate_limit() -> None:
    assert classify_gws_failure(_google_error(403, api_status="RESOURCE_EXHAUSTED")) == "rate_limit"


def test_a_403_whose_body_names_a_permission_reason_stays_permission() -> None:
    exc = _google_error(403, "insufficientPermissions")
    assert classify_gws_failure(exc) == "permission"
    assert is_skippable(exc)


def test_other_statuses_keep_their_code() -> None:
    assert classify_gws_failure(_http_error(404)) == "http_404"


def test_transport_errors_are_network() -> None:
    assert classify_gws_failure(httpx.ConnectError("refused")) == "network"
    assert classify_gws_failure(TimeoutError("slow")) == "network"


def test_an_unrecognized_exception_is_unknown() -> None:
    assert classify_gws_failure(ValueError("???")) == "unknown"


# -- health --------------------------------------------------------------


class _StubTransport:
    """Serves a canned body (or raises a canned error) per path substring."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.paths.append(path)
        for needle, value in self.responses.items():
            if needle in path:
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        raise AssertionError("health probes must not paginate")


def _client(**overrides: Any) -> tuple[GoogleWorkspaceClient, _StubTransport]:
    responses: dict[str, Any] = {
        "/domains/acme.example": {"domainName": "acme.example"},
        "/users?": {"users": []},
        "/groups?": {"groups": []},
        "/roles?": {"items": []},
        "/drives?": {"drives": []},
        "applications/login": {"items": []},
    }
    responses.update(overrides)
    transport = _StubTransport(responses)
    return GoogleWorkspaceClient(transport, domain="acme.example"), transport


def test_healthy_when_every_probe_succeeds() -> None:
    client, transport = _client()
    result = check_health(client)
    assert result.healthy is True
    assert result.message == "Google Workspace reachable with all required scopes"
    assert set(result.checked_permissions) == {
        "directory.domain",
        "directory.users",
        "directory.groups",
        "directory.roles",
        "drive.drives",
        "reports.login",
    }
    assert all(result.checked_permissions.values())
    assert len(transport.paths) == 6


def test_reports_permission_failure_degrades_but_stays_healthy() -> None:
    client, _ = _client(**{"applications/login": _http_error(403)})
    result = check_health(client)
    assert result.healthy is True
    assert result.checked_permissions["reports.login"] is False
    assert "Admin Reports unavailable (permission)" in result.message


def test_authentication_failure_names_the_delegation_settings() -> None:
    client, _ = _client(**{"/users?": _http_error(401), "/drives?": _http_error(403)})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Authentication failed for: directory.users (authentication)")
    assert "domain-wide delegation" in result.message


def test_missing_scope_fails_with_a_permission_message() -> None:
    client, _ = _client(**{"/drives?": _http_error(403)})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Permission denied for: drive.drives (permission)")


def test_required_failure_summary_ignores_the_optional_reports_probe() -> None:
    client, _ = _client(**{"/roles?": _http_error(429), "applications/login": _http_error(403)})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Google API rate limit hit for: directory.roles (rate_limit)")
    assert "reports.login" not in result.message


def test_network_failure_is_reported_as_a_network_error() -> None:
    client, _ = _client(**{"/domains/acme.example": httpx.ConnectError("no route")})
    result = check_health(client)
    assert result.healthy is False
    assert result.message.startswith("Network error reaching Google for: directory.domain (network)")


def test_unclassified_failures_use_the_generic_message() -> None:
    client, _ = _client(**{"/groups?": _http_error(500)})
    result = check_health(client)
    assert result.healthy is False
    assert result.message == "Unreachable or missing scopes for: directory.groups (http_500)"


# -- service-account JSON -------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        ("", "is required"),
        ("{not json", "not valid JSON"),
        ("[1, 2]", "must be a JSON object"),
        (json.dumps({"type": "authorized_user"}), "type must be 'service_account'"),
        (json.dumps({"private_key": "k"}), "missing client_email"),
        (json.dumps({"client_email": "a@b.c"}), "missing private_key"),
        (json.dumps({"client_email": "a@b.c", "private_key": "k", "token_uri": 7}), "empty token_uri"),
    ],
)
def test_malformed_service_account_json_is_rejected(raw: str, match: str) -> None:
    with pytest.raises(GoogleWorkspaceAuthError, match=match):
        parse_service_account_json(raw)


def test_a_plain_http_token_uri_is_rejected() -> None:
    raw = json.dumps({"client_email": "a@b.c", "private_key": "k", "token_uri": "http://oauth2.googleapis.com/token"})
    with pytest.raises(GoogleWorkspaceAuthError, match="https"):
        parse_service_account_json(raw)


@pytest.mark.usefixtures("public_dns")
def test_a_non_google_token_uri_is_rejected() -> None:
    raw = json.dumps({"client_email": "a@b.c", "private_key": "k", "token_uri": "https://evil.example/token"})
    with pytest.raises(GoogleWorkspaceAuthError, match="host not allowed"):
        parse_service_account_json(raw)


@pytest.mark.usefixtures("public_dns")
def test_parsed_service_account_is_normalized() -> None:
    escaped_pem = "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----"
    raw = json.dumps({"client_email": "  sa@p.iam.gserviceaccount.com ", "private_key": escaped_pem})
    parsed = parse_service_account_json(raw)
    assert parsed == {
        "client_email": "sa@p.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        "token_uri": DEFAULT_TOKEN_URI,
    }


# -- token minting --------------------------------------------------------


def _token_client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.usefixtures("public_dns")
def test_mint_signs_a_delegated_jwt_and_exchanges_it(rsa_key: rsa.RSAPrivateKey) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"access_token": " ya29.token "})

    with _token_client(handler) as http_client:
        token = mint_access_token_from_service_account(
            service_account_json=_sa_json(rsa_key),
            delegated_admin_email="admin@acme.example",
            scopes=("scope-a", "scope-b"),
            http_client=http_client,
            now=1_700_000_000,
        )

    assert token == "ya29.token"
    assert len(seen) == 1
    assert str(seen[0].url) == DEFAULT_TOKEN_URI
    form = parse_qs(seen[0].content.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    claims = jwt.decode(
        form["assertion"][0],
        rsa_key.public_key(),
        algorithms=["RS256"],
        audience=DEFAULT_TOKEN_URI,
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims == {
        "iss": "kestrel@acme-project.iam.gserviceaccount.com",
        "sub": "admin@acme.example",
        "aud": DEFAULT_TOKEN_URI,
        "iat": 1_700_000_000,
        "exp": 1_700_003_600,
        "scope": "scope-a scope-b",
    }


@pytest.mark.parametrize("subject", ["", "   ", "not-an-email"])
def test_mint_requires_an_admin_email_to_impersonate(subject: str) -> None:
    with pytest.raises(GoogleWorkspaceAuthError, match="delegated_admin_email"):
        mint_access_token_from_service_account(service_account_json="{}", delegated_admin_email=subject)


def test_mint_requires_at_least_one_scope() -> None:
    with pytest.raises(GoogleWorkspaceAuthError, match="scope"):
        mint_access_token_from_service_account(
            service_account_json="{}", delegated_admin_email="admin@acme.example", scopes=()
        )


@pytest.mark.usefixtures("public_dns")
def test_mint_reports_an_unusable_private_key() -> None:
    raw = json.dumps({"client_email": "sa@p.iam.gserviceaccount.com", "private_key": "not a pem"})
    with pytest.raises(GoogleWorkspaceAuthError, match="Could not sign"):
        mint_access_token_from_service_account(service_account_json=raw, delegated_admin_email="admin@acme.example", now=0)


@pytest.mark.usefixtures("public_dns")
def test_mint_surfaces_a_rejected_exchange(rsa_key: rsa.RSAPrivateKey) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text='{"error": "unauthorized_client"}')

    with (
        _token_client(handler) as http_client,
        pytest.raises(GoogleWorkspaceAuthError, match=r"\(400\).*unauthorized_client"),
    ):
        mint_access_token_from_service_account(
            service_account_json=_sa_json(rsa_key),
            delegated_admin_email="admin@acme.example",
            http_client=http_client,
            now=0,
        )


@pytest.mark.usefixtures("public_dns")
def test_mint_rejects_a_response_without_a_token(rsa_key: rsa.RSAPrivateKey) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    with _token_client(handler) as http_client, pytest.raises(GoogleWorkspaceAuthError, match="missing access_token"):
        mint_access_token_from_service_account(
            service_account_json=_sa_json(rsa_key),
            delegated_admin_email="admin@acme.example",
            http_client=http_client,
            now=0,
        )


@pytest.mark.usefixtures("public_dns")
def test_mint_wraps_transport_failures(rsa_key: rsa.RSAPrivateKey) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    with _token_client(handler) as http_client, pytest.raises(GoogleWorkspaceAuthError, match="token exchange failed"):
        mint_access_token_from_service_account(
            service_account_json=_sa_json(rsa_key),
            delegated_admin_email="admin@acme.example",
            http_client=http_client,
            now=0,
        )


# -- live transport -------------------------------------------------------


@pytest.mark.usefixtures("public_dns")
def test_a_pre_minted_access_token_is_used_directly() -> None:
    transport = build_live_transport({"access_token": " ya29.preminted ", "service_account_json": "ignored"})
    try:
        assert str(transport.client.base_url).rstrip("/") == GOOGLE_API_BASE_URL
        assert transport.client.headers["Authorization"] == "Bearer ya29.preminted"
    finally:
        transport.client.close()


@pytest.mark.parametrize(
    "secrets",
    [{}, {"service_account_json": "{}"}, {"delegated_admin_email": "admin@acme.example"}, {"access_token": "  "}],
)
def test_live_transport_refuses_to_run_without_credentials(secrets: dict[str, str]) -> None:
    with pytest.raises(LiveAuthNotConfiguredError, match="service_account_json"):
        build_live_transport(secrets)


@pytest.mark.usefixtures("public_dns")
def test_service_account_credentials_fail_fast_on_a_bad_key() -> None:
    # The first mint happens at build time, so a broken key surfaces at
    # Test connection rather than mid-sync.
    secrets = {
        "service_account_json": json.dumps({"client_email": "sa@p.iam.gserviceaccount.com", "private_key": "bad"}),
        "delegated_admin_email": "admin@acme.example",
    }
    with pytest.raises(GoogleWorkspaceAuthError, match="Could not sign"):
        build_live_transport(secrets)
