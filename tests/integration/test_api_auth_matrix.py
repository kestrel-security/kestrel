# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""One authorization matrix for the whole HTTP surface.

`ENDPOINTS` is a table of `(method, path_template, minimum_role)`. A single
parametrized test walks it and asserts the RBAC contract every route in
`apps/api/src/kestrel_api/routers/` is supposed to honour:

- No `Authorization` header -> 401.
- Authenticated below `minimum_role` -> 403.
- Authenticated at `minimum_role` -> not 403 (the route's own logic then
  takes over: 200, 404 for a made-up id, 422 for a body the row doesn't
  happen to satisfy -- anything but a role rejection).

Path placeholders (`{finding_id}`, `{policy_id}`, ...) are filled with a
fresh random id per request. This deliberately never resolves to a real row:
the matrix is only about who is *allowed to ask*, not about response bodies
-- per-router behavior tests (`test_api_findings.py`, `test_api_policies.py`,
...) cover real objects. A 404 for a made-up id is a perfectly valid
"not 403" outcome and is exactly what most at-or-above-role rows return here.

Adding an endpoint to the API means adding one row below.

One route takes no authentication by design (`GET /changes/classes` is a
static vocabulary list) and `POST /auth/login` *is* the credential exchange --
both are exercised in their own router test files, not here.
"""

from __future__ import annotations

import re
import uuid

import pytest
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

# (method, path template, minimum role required)
ENDPOINTS: list[tuple[str, str, str]] = [
    # -- auth --
    ("POST", "/api/v1/auth/logout", "read_only"),
    ("GET", "/api/v1/auth/me", "read_only"),
    ("POST", "/api/v1/auth/change-password", "read_only"),
    ("GET", "/api/v1/auth/mfa", "read_only"),
    ("POST", "/api/v1/auth/mfa/setup", "read_only"),
    ("POST", "/api/v1/auth/mfa/activate", "read_only"),
    ("POST", "/api/v1/auth/mfa/disable", "read_only"),
    ("POST", "/api/v1/auth/mfa/recovery-codes", "read_only"),
    ("GET", "/api/v1/org/security", "admin"),
    ("PATCH", "/api/v1/org/security", "admin"),
    ("POST", "/api/v1/operators/{id}/mfa/reset", "admin"),
    # -- operators --
    ("GET", "/api/v1/operators", "read_only"),
    ("GET", "/api/v1/operators/{id}", "read_only"),
    ("POST", "/api/v1/operators", "admin"),
    ("PATCH", "/api/v1/operators/{id}", "admin"),
    ("POST", "/api/v1/operators/{id}/set-password", "admin"),
    # -- api-tokens --
    ("GET", "/api/v1/api-tokens", "read_only"),
    ("POST", "/api/v1/api-tokens", "read_only"),
    ("DELETE", "/api/v1/api-tokens/{id}", "read_only"),
    # -- notification-preferences --
    ("GET", "/api/v1/notification-preferences", "read_only"),
    ("PATCH", "/api/v1/notification-preferences", "read_only"),
    # -- notifications (the caller's own inbox) --
    ("GET", "/api/v1/notifications", "read_only"),
    ("GET", "/api/v1/notifications/unread-count", "read_only"),
    ("POST", "/api/v1/notifications/read-all", "read_only"),
    ("POST", "/api/v1/notifications/{id}/read", "read_only"),
    # -- settings/ai --
    ("GET", "/api/v1/settings/ai", "admin"),
    ("PUT", "/api/v1/settings/ai", "admin"),
    ("DELETE", "/api/v1/settings/ai", "admin"),
    # -- settings/email --
    ("GET", "/api/v1/settings/email", "admin"),
    ("PUT", "/api/v1/settings/email", "admin"),
    ("DELETE", "/api/v1/settings/email", "admin"),
    ("POST", "/api/v1/settings/email/test", "admin"),
    # -- audit-log --
    ("GET", "/api/v1/audit-log", "admin"),
    ("GET", "/api/v1/audit-log/export", "admin"),
    # -- changes --
    ("GET", "/api/v1/changes", "read_only"),
    # -- dashboard (singular: posture overview + per-operator layout) --
    ("GET", "/api/v1/dashboard", "read_only"),
    ("GET", "/api/v1/dashboard/layout", "read_only"),
    ("PUT", "/api/v1/dashboard/layout", "read_only"),
    ("POST", "/api/v1/dashboard/layout/reset", "read_only"),
    ("POST", "/api/v1/dashboard/first-run/dismiss", "read_only"),
    ("POST", "/api/v1/dashboard/first-run/restore", "read_only"),
    # -- dashboards (plural: multi-dashboard) --
    ("GET", "/api/v1/dashboards", "read_only"),
    ("GET", "/api/v1/dashboards/presets", "read_only"),
    ("POST", "/api/v1/dashboards/query/preview", "analyst"),
    ("POST", "/api/v1/dashboards/pin-home", "read_only"),
    ("POST", "/api/v1/dashboards", "analyst"),
    ("GET", "/api/v1/dashboards/{id}", "read_only"),
    ("PATCH", "/api/v1/dashboards/{id}", "analyst"),
    ("DELETE", "/api/v1/dashboards/{id}", "analyst"),
    ("POST", "/api/v1/dashboards/{id}/duplicate", "analyst"),
    ("POST", "/api/v1/dashboards/{id}/set-default", "admin"),
    ("PUT", "/api/v1/dashboards/{id}/layout", "analyst"),
    ("POST", "/api/v1/dashboards/{id}/widgets", "analyst"),
    ("PATCH", "/api/v1/dashboards/{id}/widgets/{id}", "analyst"),
    ("DELETE", "/api/v1/dashboards/{id}/widgets/{id}", "analyst"),
    ("POST", "/api/v1/dashboards/{id}/export", "read_only"),
    ("GET", "/api/v1/dashboards/{id}/schedules", "admin"),
    ("POST", "/api/v1/dashboards/{id}/schedules", "admin"),
    ("PATCH", "/api/v1/dashboards/{id}/schedules/{id}", "admin"),
    ("DELETE", "/api/v1/dashboards/{id}/schedules/{id}", "admin"),
    # -- packs --
    ("GET", "/api/v1/packs", "read_only"),
    ("GET", "/api/v1/packs/{name}", "read_only"),
    ("GET", "/api/v1/packs/{name}/install-preview", "read_only"),
    ("POST", "/api/v1/packs/{name}/install", "analyst"),
    ("GET", "/api/v1/packs/{name}/coverage", "read_only"),
    ("POST", "/api/v1/packs/{name}/enable", "analyst"),
    ("POST", "/api/v1/packs/{name}/disable", "analyst"),
    # -- policies --
    ("GET", "/api/v1/policies", "read_only"),
    ("POST", "/api/v1/policies/generate", "analyst"),
    ("GET", "/api/v1/policies/generate/catalog", "analyst"),
    ("GET", "/api/v1/policies/{id}", "read_only"),
    ("GET", "/api/v1/policies/{id}/fixtures", "read_only"),
    ("PUT", "/api/v1/policies/{id}/fixtures", "analyst"),
    ("POST", "/api/v1/policies/fixtures/from-matches", "analyst"),
    ("POST", "/api/v1/policies/{id}/fixtures/from-matches", "analyst"),
    ("GET", "/api/v1/policies/{id}/evaluations", "read_only"),
    ("GET", "/api/v1/policies/{id}/findings", "read_only"),
    ("POST", "/api/v1/policies", "analyst"),
    ("POST", "/api/v1/policies/{id}/fork", "analyst"),
    ("POST", "/api/v1/policies/{id}/versions", "analyst"),
    ("GET", "/api/v1/policies/{id}/versions", "read_only"),
    ("POST", "/api/v1/policies/{id}/versions/{id}/activate", "analyst"),
    ("PATCH", "/api/v1/policies/{id}", "analyst"),
    ("DELETE", "/api/v1/policies/{id}", "analyst"),
    ("POST", "/api/v1/policies/validate", "analyst"),
    ("POST", "/api/v1/policies/{id}/test", "analyst"),
    ("POST", "/api/v1/policies/test-draft", "analyst"),
    ("POST", "/api/v1/policies/dry-run-draft", "analyst"),
    ("POST", "/api/v1/policies/{id}/dry-run", "analyst"),
    ("POST", "/api/v1/policies/{id}/evaluate", "analyst"),
    # -- connectors / connector-instances / connector-runs --
    ("GET", "/api/v1/connectors", "read_only"),
    ("GET", "/api/v1/connector-instances/health", "read_only"),
    ("GET", "/api/v1/connector-instances", "read_only"),
    ("GET", "/api/v1/connector-instances/{id}", "read_only"),
    ("POST", "/api/v1/connector-instances", "analyst"),
    ("DELETE", "/api/v1/connector-instances/{id}", "analyst"),
    ("PATCH", "/api/v1/connector-instances/{id}", "analyst"),
    ("GET", "/api/v1/connector-instances/{id}/secrets", "read_only"),
    ("PUT", "/api/v1/connector-instances/{id}/secrets", "analyst"),
    ("PATCH", "/api/v1/connector-instances/{id}/schedule", "analyst"),
    ("POST", "/api/v1/connector-instances/{id}/test-connection", "analyst"),
    ("POST", "/api/v1/connectors/probe", "analyst"),
    ("POST", "/api/v1/connector-instances/{id}/sync", "analyst"),
    ("GET", "/api/v1/connector-instances/{id}/runs", "read_only"),
    ("GET", "/api/v1/connector-runs/{id}", "read_only"),
    ("GET", "/api/v1/connector-runs/{id}/changes", "read_only"),
    # -- resources --
    ("GET", "/api/v1/resources", "read_only"),
    ("GET", "/api/v1/resources/{id}", "read_only"),
    ("PATCH", "/api/v1/resources/{id}/sensitivity", "analyst"),
    # -- identities --
    ("GET", "/api/v1/identities", "read_only"),
    ("GET", "/api/v1/identities/correlated", "read_only"),
    ("GET", "/api/v1/identities/{id}", "read_only"),
    ("GET", "/api/v1/identities/{id}/access", "read_only"),
    ("GET", "/api/v1/identities/{id}/overview", "read_only"),
    # -- graph --
    ("GET", "/api/v1/graph/resolve?node_type=identity&object_id={id}", "read_only"),
    ("GET", "/api/v1/graph/search?q=x", "read_only"),
    ("GET", "/api/v1/graph/nodes/{id}/neighbors", "read_only"),
    ("GET", "/api/v1/graph/nodes/{id}/paths", "read_only"),
    ("GET", "/api/v1/graph/nodes/{id}/context", "read_only"),
    ("GET", "/api/v1/graph/edges/{id}", "read_only"),
    # -- search --
    ("GET", "/api/v1/search", "read_only"),
    # -- ticket-integrations --
    ("GET", "/api/v1/ticket-integrations/providers", "analyst"),
    ("GET", "/api/v1/ticket-integrations", "analyst"),
    ("POST", "/api/v1/ticket-integrations", "admin"),
    ("GET", "/api/v1/ticket-integrations/{id}", "admin"),
    ("PATCH", "/api/v1/ticket-integrations/{id}", "admin"),
    ("POST", "/api/v1/ticket-integrations/{id}/rotate-token", "admin"),
    ("DELETE", "/api/v1/ticket-integrations/{id}", "admin"),
    # -- webhooks --
    ("GET", "/api/v1/webhooks", "admin"),
    ("POST", "/api/v1/webhooks", "admin"),
    ("GET", "/api/v1/webhooks/{id}", "admin"),
    ("PATCH", "/api/v1/webhooks/{id}", "admin"),
    ("DELETE", "/api/v1/webhooks/{id}", "admin"),
    ("POST", "/api/v1/webhooks/{id}/rotate-secret", "admin"),
    ("GET", "/api/v1/webhooks/{id}/deliveries", "admin"),
    ("POST", "/api/v1/webhooks/{id}/deliveries/{id}/retry", "admin"),
    # -- findings --
    ("GET", "/api/v1/findings/queues", "read_only"),
    ("GET", "/api/v1/findings/exceptions/expiring", "read_only"),
    ("GET", "/api/v1/findings/mutes/expiring", "read_only"),
    ("GET", "/api/v1/findings/watched", "read_only"),
    ("GET", "/api/v1/findings/watched/digest", "read_only"),
    ("POST", "/api/v1/findings/watched/digest-preview", "read_only"),
    ("GET", "/api/v1/findings/presets", "read_only"),
    ("POST", "/api/v1/findings/presets", "read_only"),
    ("PATCH", "/api/v1/findings/presets/{id}", "read_only"),
    ("POST", "/api/v1/findings/presets/{id}/use", "read_only"),
    ("DELETE", "/api/v1/findings/presets/{id}", "read_only"),
    ("GET", "/api/v1/findings", "read_only"),
    ("GET", "/api/v1/findings/export", "read_only"),
    ("POST", "/api/v1/findings/bulk", "analyst"),
    ("GET", "/api/v1/findings/{id}/handoff", "read_only"),
    ("GET", "/api/v1/findings/{id}/provenance", "read_only"),
    ("GET", "/api/v1/findings/{id}/attack-path", "read_only"),
    ("GET", "/api/v1/findings/{id}/blast-radius/export", "read_only"),
    ("GET", "/api/v1/findings/{id}", "read_only"),
    ("PATCH", "/api/v1/findings/{id}", "analyst"),
    ("POST", "/api/v1/findings/{id}/exceptions", "analyst"),
    ("GET", "/api/v1/findings/{id}/notes", "read_only"),
    ("POST", "/api/v1/findings/{id}/notes", "analyst"),
    ("GET", "/api/v1/findings/{id}/tickets", "read_only"),
    ("POST", "/api/v1/findings/{id}/tickets", "analyst"),
    ("POST", "/api/v1/findings/{id}/mute", "analyst"),
    ("POST", "/api/v1/findings/{id}/unmute", "analyst"),
    ("POST", "/api/v1/findings/{id}/verify", "analyst"),
    ("GET", "/api/v1/findings/{id}/watch", "read_only"),
    ("POST", "/api/v1/findings/{id}/watch", "read_only"),
    ("DELETE", "/api/v1/findings/{id}/watch", "read_only"),
]

_ROLE_RANK = {"read_only": 0, "analyst": 1, "admin": 2}
_ROLE_BELOW = {"analyst": "read_only", "admin": "analyst"}

_ID_RE = re.compile(r"\{id\}")
_NAME_RE = re.compile(r"\{name\}")


def _fill_path(template: str) -> str:
    """Fresh random ids per call -- a made-up id resolving to 404 is the
    point, not an accident (see module docstring)."""
    path = _ID_RE.sub(lambda _m: str(uuid.uuid4()), template)
    path = _NAME_RE.sub(lambda _m: f"does-not-exist-{uuid.uuid4().hex[:8]}", path)
    return path


def _ids() -> list[str]:
    return [f"{m} {p}" for m, p, _r in ENDPOINTS]


@pytest.mark.parametrize(("method", "path_template", "min_role"), ENDPOINTS, ids=_ids())
def test_requires_authentication(db_session, method, path_template, min_role):
    """No Authorization header -> 401, regardless of role requirement."""
    client = api_client(db_session, OperatorRole.ADMIN)
    path = _fill_path(path_template)
    body = {} if method in ("POST", "PATCH", "PUT") else None
    response = client.request(method, path, headers={"Authorization": ""}, json=body)
    assert response.status_code == 401


#: Endpoints open to the floor role have no role below it to reject.
_GATED_ENDPOINTS = [e for e in ENDPOINTS if _ROLE_BELOW.get(e[2]) is not None]


@pytest.mark.parametrize(
    ("method", "path_template", "min_role"), _GATED_ENDPOINTS, ids=[f"{m} {p}" for m, p, _r in _GATED_ENDPOINTS]
)
def test_rejects_below_minimum_role(db_session, method, path_template, min_role):
    """Authenticated but under-privileged -> 403."""
    below = _ROLE_BELOW[min_role]
    client = api_client(db_session, OperatorRole(below))
    path = _fill_path(path_template)
    response = client.request(method, path, json={} if method in ("POST", "PATCH", "PUT") else None)
    assert response.status_code == 403


@pytest.mark.parametrize(("method", "path_template", "min_role"), ENDPOINTS, ids=_ids())
def test_allows_at_minimum_role(db_session, method, path_template, min_role):
    """Authenticated at exactly the minimum role -> never a role rejection.

    The made-up path id means the route's own logic almost always answers
    with 404 (or occasionally 422 for a body the placeholder request does
    not satisfy) -- anything but 403.
    """
    client = api_client(db_session, OperatorRole(min_role))
    path = _fill_path(path_template)
    response = client.request(method, path, json={} if method in ("POST", "PATCH", "PUT") else None)
    assert response.status_code != 403


#: Routes that deliberately take no authentication. Each is exercised in its
#: own router test file; they are listed here so the completeness check below
#: can tell "intentionally open" from "someone forgot a row".
UNAUTHENTICATED: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/v1/auth/login"),  # the credential exchange itself
        # Takes the short-lived challenge token a login returns, never a
        # session; a full session gets 403. Covered in test_mfa.py.
        ("POST", "/api/v1/auth/login/mfa"),
        ("GET", "/api/v1/changes/classes"),  # static vocabulary, no org data
    }
)

_PATH_PARAM = re.compile(r"\{[^}]*\}")


def _canonical(method: str, path: str) -> tuple[str, str]:
    """Compare on shape alone.

    The matrix writes `{id}` where OpenAPI writes `{operator_id}`, and two rows
    carry query strings the schema does not, so neither difference should read
    as a coverage gap.
    """
    return method.upper(), _PATH_PARAM.sub("{}", path.split("?", 1)[0])


def test_every_endpoint_is_in_the_matrix_or_declared_unauthenticated():
    """The matrix is only a contract if it cannot silently fall behind.

    Nothing stopped a new route from shipping without a row: the parametrized
    tests above only walk what is already in `ENDPOINTS`, so an endpoint nobody
    listed is an endpoint nobody checks for 401/403. This fails instead, and
    names the exact rows to add.
    """
    from kestrel_api.main import create_app

    schema = create_app().openapi()
    live = {
        _canonical(method, path)
        for path, operations in schema["paths"].items()
        for method in operations
        if method.upper() in {"GET", "POST", "PATCH", "PUT", "DELETE"} and path.startswith("/api/v1")
    }
    declared = {_canonical(m, p) for m, p, _ in ENDPOINTS} | {_canonical(m, p) for m, p in UNAUTHENTICATED}

    missing = sorted(live - declared)
    assert not missing, (
        "these endpoints exist but are in neither ENDPOINTS nor UNAUTHENTICATED, "
        f"so nothing asserts their authorization contract: {missing}"
    )

    stale = sorted(declared - live)
    assert not stale, f"these rows no longer correspond to a live endpoint and should be removed: {stale}"
