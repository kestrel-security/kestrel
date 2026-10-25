# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Translates OktaClient responses into RawObjects.

Cross-cutting joins (group membership, MFA factors, admin roles, app
assignments including **group → app**) are stitched here so the normalizer
stays a pure mapping.

**Gated families degrade visibly.** An Okta API token inherits its creating
admin's permissions, so a token made by a non-super admin can read the
directory but not `/api/v1/api-tokens`, `/api/v1/logs`, or policies. Those
families skip on 403/404 -- and record the skip on ``skipped_object_types``,
which the sync pipeline reads to downgrade the run to PARTIAL_FAILURE and
suppress deletion detection. Returning an empty list without recording it
(what this collector did ) reports an incomplete inventory as a
complete one, and `detect_deletions` reads the absent rows as removal --
filling `/changes` with revocations that never happened.

A rate-limited request is not a gate and does not skip; see `http.is_skippable`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.base import HealthCheckResult, RawObject
from kestrel.connectors.sdk.payload import reduce_url_to_host, sub_dict

from kestrel_connector_okta.client import OktaClient
from kestrel_connector_okta.health import check_health
from kestrel_connector_okta.http import classify_okta_failure, is_skippable

# Classic Okta admin roles we materialize as privileged Kestrel roles.
# Names for SUPER/ORG/APP/HELP_DESK/GROUP must stay stable: okta-posture
# policies match these display names.
# Per-user fan-out bound (factors, roles). Okta's per-endpoint limit is
# hundreds of requests a minute; six workers stay well inside it while the
# transport backs off on any 429.
FAN_OUT_WORKERS = 6

ADMIN_ROLES: dict[str, str] = {
    "SUPER_ADMIN": "Super Administrator",
    "ORG_ADMIN": "Organization Administrator",
    "APP_ADMIN": "Application Administrator",
    "USER_ADMIN": "User Administrator",
    "HELP_DESK_ADMIN": "Help Desk Administrator",
    "GROUP_ADMIN": "Group Administrator",
    "GROUP_MEMBERSHIP_ADMIN": "Group Membership Administrator",
    "READ_ONLY_ADMIN": "Read-Only Administrator",
    "MOBILE_ADMIN": "Mobile Administrator",
    "API_ACCESS_MANAGEMENT_ADMIN": "API Access Management Administrator",
    "REPORT_ADMIN": "Report Administrator",
}

OBJECT_TYPES = [
    "org",
    "user",
    "group",
    "group_member",
    "admin_role",
    "role_assignment",
    "app",
    "app_scope",
    "app_group",
    "app_user",
    "system_log",
    "password_policy",
    "mfa_enroll_policy",
    "threat_insight",
    "api_token",
    "app_sign_on_setting",
    # -- authentication and session policy surface ---------------
    "access_policy",
    "sign_on_policy",
    "profile_enrollment_policy",
    "idp_discovery_policy",
    "entity_risk_policy",
    "post_auth_session_policy",
    "authenticator",
    "device_assurance_policy",
    # -- perimeter and automation surface ------------------------
    "network_zone",
    "trusted_origin",
    "event_hook",
    "inline_hook",
    "identity_provider",
    "group_rule",
    # -- privilege model (extended) ----------------------------
    "iam_role",
    "resource_set",
    # -- security behaviors (extended) -------------------------
    "behavior",
    # -- infrastructure (extended) -----------------------------
    "log_stream",
    "auth_server",
    # -- devices (extended) ------------------------------------
    "device",
]

# Policy types Kestrel reads beyond PASSWORD and MFA_ENROLL, mapped to the
# object type that carries them. Each is collected with its rules attached,
# because an Okta policy is a container and the controls live in the rules.
_POLICY_TYPE_BY_OBJECT_TYPE: dict[str, str] = {
    "access_policy": "ACCESS_POLICY",
    "sign_on_policy": "OKTA_SIGN_ON",
    "profile_enrollment_policy": "PROFILE_ENROLLMENT",
    "idp_discovery_policy": "IDP_DISCOVERY",
    "entity_risk_policy": "ENTITY_RISK",
    "post_auth_session_policy": "POST_AUTH_SESSION",
}

# Families whose absence degrades the run rather than failing it. Everything
# else is core directory inventory: a 403 there means the token's admin cannot
# read the org at all, and the health check's permission message is the right
# way to surface that.
#
# All families need more than the default admin grant — System Log and API tokens
# effectively need Super Admin, policy reads need policy permissions, and
# ThreatInsight is feature-gated. Extended families (behaviors, log_stream,
# auth_server, iam_role, resource_set, device) all require OAuth scopes that
# are unavailable to classic SSWS tokens without Super Admin.
OPTIONAL_OBJECT_TYPES = frozenset(
    {
        "system_log",
        "threat_insight",
        "api_token",
        "password_policy",
        "mfa_enroll_policy",
        "access_policy",
        "sign_on_policy",
        "profile_enrollment_policy",
        "idp_discovery_policy",
        "entity_risk_policy",
        "post_auth_session_policy",
        "authenticator",
        "device_assurance_policy",
        "network_zone",
        "trusted_origin",
        "event_hook",
        "inline_hook",
        "identity_provider",
        "group_rule",
        # Optional extended families
        "iam_role",
        "resource_set",
        "behavior",
        "log_stream",
        "auth_server",
        "device",
    }
)


def _redact_hook(hook: dict[str, Any]) -> dict[str, Any]:
    """A hook payload with its callout URL reduced to a host.

    Okta hook URLs carry authentication in the path or in headers, and an
    inline hook's endpoint can change the outcome of a sign-in -- so the URL is
    both a secret and the most sensitive field in the payload. Redacted here,
    at collection, because `raw_source` is persisted verbatim.
    """
    redacted = dict(hook)
    channel = dict(hook.get("channel") or {})
    config = reduce_url_to_host(channel.get("config") or {}, "uri")
    # Okta returns auth headers on hook definitions; never store them.
    config.pop("authScheme", None)
    config.pop("headers", None)
    channel["config"] = config
    redacted["channel"] = channel
    return redacted


def _user_has_active_mfa(factors: list[dict[str, Any]]) -> bool | None:
    if not factors:
        return False
    return any(str(f.get("status", "")).upper() == "ACTIVE" for f in factors)


def _is_deprovisioned(user: dict[str, Any]) -> bool:
    return str(user.get("status") or "").upper() == "DEPROVISIONED"


class OktaCollector:
    def __init__(self, client: OktaClient) -> None:
        self.client = client
        # object_type / sub-family -> failure class, read by the sync pipeline.
        self.skipped_object_types: dict[str, str] = {}

    def discover(self) -> list[str]:
        return list(OBJECT_TYPES)

    def health_check(self) -> HealthCheckResult:
        return check_health(self.client)

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        method = getattr(self, f"_collect_{object_type}", None)
        if method is None:
            raise ValueError(f"OktaCollector does not support object_type '{object_type}'")
        try:
            if object_type == "system_log":
                yield from self._collect_system_log(datetime.now(UTC), since=since)
                return
            del since
            yield from method(datetime.now(UTC))
        except Exception as exc:
            if object_type in OPTIONAL_OBJECT_TYPES and is_skippable(exc):
                self.skipped_object_types[object_type] = classify_okta_failure(exc)
                return
            raise

    def _safe_list(self, family: str, fn: Callable[..., list[dict[str, Any]]], *args: str) -> list[dict[str, Any]]:
        """A nested per-entity call that may be gated for the whole family.

        `family` is the sub-family label recorded once on the first skip, not
        once per entity -- a token that cannot read one user's roles cannot read
        any of them, so N identical entries would be noise.
        """
        try:
            return list(fn(*args))
        except Exception as exc:
            if not is_skippable(exc):
                raise
            self.skipped_object_types.setdefault(family, classify_okta_failure(exc))
            return []

    def _collect_org(self, now: datetime) -> Iterable[RawObject]:
        org = self.client.get_org()
        org_id = str(org.get("id") or org.get("subdomain") or "default")
        yield RawObject(object_type="org", provider_id=org_id, payload=org, collected_at=now)

    def _fan_out(
        self,
        family: str,
        fn: Callable[[str], list[dict[str, Any]]],
        ids: list[str],
    ) -> dict[str, list[dict[str, Any]]]:
        """Bounded parallel per-id listing with the same skip semantics as
        ``_safe_list``. One call per user for factors and roles is the cost of
        the Okta API shape; a small pool keeps a large directory inside the
        sync time budget without tripping the per-endpoint rate limit, which
        the transport still honors per request."""
        results: dict[str, list[dict[str, Any]]] = {}
        if not ids:
            return results

        def one(item_id: str) -> tuple[str, list[dict[str, Any]] | None, BaseException | None]:
            try:
                return item_id, list(fn(item_id)), None
            except Exception as exc:  # noqa: BLE001 -- handed to the collector thread, which re-raises it unless skippable
                return item_id, None, exc

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=FAN_OUT_WORKERS) as pool:
            for item_id, rows, exc in pool.map(one, ids):
                if exc is not None:
                    if not is_skippable(exc):
                        raise exc
                    self.skipped_object_types.setdefault(family, classify_okta_failure(exc))
                    results[item_id] = []
                    continue
                results[item_id] = rows or []
        return results

    def _collect_user(self, now: datetime) -> Iterable[RawObject]:
        users = self.client.list_users()
        needs_factors = [str(u["id"]) for u in users if not isinstance(u.get("factors"), list)]
        fetched = self._fan_out("user.factors", self.client.list_user_factors, needs_factors)
        for user in users:
            user_id = str(user["id"])
            # Prefer embedded factors; fall back to the factors endpoint.
            factors = user.get("factors")
            if not isinstance(factors, list):
                factors = fetched.get(user_id, [])
            payload = dict(user)
            payload["factors"] = factors
            payload["mfa_enabled"] = _user_has_active_mfa(factors)
            yield RawObject(object_type="user", provider_id=user_id, payload=payload, collected_at=now)

    def _collect_group(self, now: datetime) -> Iterable[RawObject]:
        for group in self.client.list_groups():
            yield RawObject(
                object_type="group",
                provider_id=str(group["id"]),
                payload=group,
                collected_at=now,
            )

    def _collect_group_member(self, now: datetime) -> Iterable[RawObject]:
        for group in self.client.list_groups():
            group_id = str(group["id"])
            for user in self._safe_list("group_member.users", self.client.list_group_users, group_id):
                user_id = str(user["id"])
                yield RawObject(
                    object_type="group_member",
                    provider_id=f"{group_id}:{user_id}",
                    payload={"group_id": group_id, "user_id": user_id},
                    collected_at=now,
                )

    def _collect_admin_role(self, now: datetime) -> Iterable[RawObject]:
        for role_type, name in ADMIN_ROLES.items():
            privileged = role_type != "READ_ONLY_ADMIN"
            yield RawObject(
                object_type="admin_role",
                provider_id=role_type,
                payload={"id": role_type, "name": name, "is_privileged": privileged},
                collected_at=now,
            )

    def _role_holder_ids(self) -> list[str]:
        """User ids worth asking ``/users/{id}/roles`` about.

        ``/iam/assignees/users`` lists exactly the users holding a role, so a
        ten-thousand-user org costs a handful of calls instead of ten thousand.
        Orgs without the endpoint (404) or credentials without access (403)
        fall back to the full directory walk, which is slower, not wrong.
        """
        try:
            assignees = self.client.list_role_assignees()
        except Exception as exc:
            if not is_skippable(exc):
                raise
            return [str(u["id"]) for u in self.client.list_users()]
        ids = [str(row.get("id") or "") for row in assignees if row.get("id")]
        directory = {str(u["id"]) for u in self.client.list_users()}
        return [user_id for user_id in ids if user_id in directory]

    def _collect_role_assignment(self, now: datetime) -> Iterable[RawObject]:
        deprovisioned = {str(u["id"]) for u in self.client.list_users() if _is_deprovisioned(u)}
        seen: set[str] = set()
        holder_ids = self._role_holder_ids()
        roles_by_user = self._fan_out("role_assignment.user_roles", self.client.list_user_roles, holder_ids)

        for user_id in holder_ids:
            for role in roles_by_user.get(user_id, []):
                role_type = str(role.get("type") or role.get("id") or "")
                if role_type not in ADMIN_ROLES:
                    continue
                provider_id = f"{user_id}:{role_type}"
                if provider_id in seen:
                    continue
                seen.add(provider_id)
                yield RawObject(
                    object_type="role_assignment",
                    provider_id=provider_id,
                    payload={
                        "user_id": user_id,
                        "role_id": role_type,
                        "assignment_type": "USER",
                        "group_id": None,
                    },
                    collected_at=now,
                )

        for group in self.client.list_groups():
            group_id = str(group["id"])
            member_ids = [
                str(u["id"])
                for u in self._safe_list("role_assignment.group_users", self.client.list_group_users, group_id)
                if u.get("id") and str(u["id"]) not in deprovisioned
            ]
            for role in self._safe_list("role_assignment.group_roles", self.client.list_group_roles, group_id):
                role_type = str(role.get("type") or role.get("id") or "")
                if role_type not in ADMIN_ROLES:
                    continue
                for user_id in member_ids:
                    provider_id = f"{user_id}:{role_type}:group:{group_id}"
                    if provider_id in seen:
                        continue
                    seen.add(provider_id)
                    yield RawObject(
                        object_type="role_assignment",
                        provider_id=provider_id,
                        payload={
                            "user_id": user_id,
                            "role_id": role_type,
                            "assignment_type": "GROUP",
                            "group_id": group_id,
                        },
                        collected_at=now,
                    )

    def _collect_app(self, now: datetime) -> Iterable[RawObject]:
        for app in self.client.list_apps():
            yield RawObject(
                object_type="app",
                provider_id=str(app["id"]),
                payload=app,
                collected_at=now,
            )

    def _collect_app_scope(self, now: datetime) -> Iterable[RawObject]:
        for app in self.client.list_apps():
            app_id = str(app["id"])
            scopes = _app_scopes(app)
            if _is_service_app(app):
                # A service integration's real power is the Okta API scopes it
                # was *granted*, not the ones it lists; read them when the
                # credential can, else keep the requested list as the fallback.
                granted = [
                    str(g.get("scopeId") or "")
                    for g in self._safe_list("app_scope.grants", self.client.list_app_grants, app_id)
                    if g.get("scopeId") and str(g.get("status") or "ACTIVE").upper() == "ACTIVE"
                ]
                if granted:
                    scopes = granted
            for scope_name in scopes:
                yield RawObject(
                    object_type="app_scope",
                    provider_id=f"{app_id}:{scope_name}",
                    payload={"app_id": app_id, "scope_name": scope_name},
                    collected_at=now,
                )

    def _collect_app_group(self, now: datetime) -> Iterable[RawObject]:
        """App ← group assignments so Explore can put the group between members and apps."""
        for app in self.client.list_apps():
            app_id = str(app["id"])
            for assignment in self._safe_list("app_group.assignments", self.client.list_app_groups, app_id):
                group_id = str(assignment.get("id") or assignment.get("groupId") or "")
                if not group_id:
                    continue
                payload = dict(assignment)
                payload["app_id"] = app_id
                payload["group_id"] = group_id
                yield RawObject(
                    object_type="app_group",
                    provider_id=f"{app_id}:{group_id}",
                    payload=payload,
                    collected_at=now,
                )

    def _collect_app_user(self, now: datetime) -> Iterable[RawObject]:
        for app in self.client.list_apps():
            app_id = str(app["id"])
            for assignment in self._safe_list("app_user.assignments", self.client.list_app_users, app_id):
                user_id = str(assignment.get("id") or assignment.get("userId") or "")
                if not user_id:
                    continue
                # Group-assigned users also appear on /apps/{id}/users with
                # scope=GROUP. Skip those identity→app edges so access is the
                # 2-hop path member_of → can_access (group in the middle).
                if str(assignment.get("scope") or "").upper() == "GROUP":
                    continue
                payload = dict(assignment)
                payload["app_id"] = app_id
                payload["user_id"] = user_id
                yield RawObject(
                    object_type="app_user",
                    provider_id=f"{app_id}:{user_id}",
                    payload=payload,
                    collected_at=now,
                )

    def _collect_system_log(self, now: datetime, *, since: datetime | None = None) -> Iterable[RawObject]:
        """Okta System Log → activity events for privilege / MFA / threat-event policies.

        `system_log` is in OPTIONAL_OBJECT_TYPES, so `collect` records the skip
        and degrades the run if the token cannot read /api/v1/logs. Unmapped
        event types are collected raw; the normalizer drops noise.
        """
        for entry in self.client.list_system_logs(since=since):
            provider_id = str(entry.get("uuid") or entry.get("id") or "")
            if not provider_id:
                continue
            yield RawObject(
                object_type="system_log",
                provider_id=provider_id,
                payload=entry,
                collected_at=now,
            )

    def _collect_password_policy(self, now: datetime) -> Iterable[RawObject]:
        for policy in self.client.list_policies("PASSWORD"):
            policy_id = str(policy.get("id") or "")
            if not policy_id:
                continue
            yield RawObject(
                object_type="password_policy",
                provider_id=policy_id,
                payload=policy,
                collected_at=now,
            )

    def _collect_mfa_enroll_policy(self, now: datetime) -> Iterable[RawObject]:
        for policy in self.client.list_policies("MFA_ENROLL"):
            policy_id = str(policy.get("id") or "")
            if not policy_id:
                continue
            yield RawObject(
                object_type="mfa_enroll_policy",
                provider_id=policy_id,
                payload=policy,
                collected_at=now,
            )

    def _collect_threat_insight(self, now: datetime) -> Iterable[RawObject]:
        config = self.client.get_threat_insight_configuration()
        if not isinstance(config, dict):
            return
        yield RawObject(
            object_type="threat_insight",
            provider_id="threat-insight",
            payload=config,
            collected_at=now,
        )

    def _collect_api_token(self, now: datetime) -> Iterable[RawObject]:
        for token in self.client.list_api_tokens():
            token_id = str(token.get("id") or "")
            if not token_id:
                continue
            yield RawObject(
                object_type="api_token",
                provider_id=token_id,
                payload=token,
                collected_at=now,
            )

    def _collect_app_sign_on_setting(self, now: datetime) -> Iterable[RawObject]:
        for app in self.client.list_apps():
            app_id = str(app["id"])
            yield RawObject(
                object_type="app_sign_on_setting",
                provider_id=app_id,
                payload={
                    "app_id": app_id,
                    "name": app.get("label") or app.get("name") or app_id,
                    "signOnMode": app.get("signOnMode"),
                    "status": app.get("status"),
                },
                collected_at=now,
            )

    # -- authentication and session policy surface ----------------

    def _collect_policies_with_rules(self, now: datetime, object_type: str) -> Iterable[RawObject]:
        """One RawObject per policy, with its rules attached.

        The rules are fetched per policy, so they are a sub-family skip: an org
        where policy rules are unreadable still gets the policy inventory, and
        the gap is recorded rather than read as "this policy has no rules",
        which would look like a wide-open sign-on policy.
        """
        policy_type = _POLICY_TYPE_BY_OBJECT_TYPE[object_type]
        for policy in self.client.list_policies(policy_type):
            policy_id = str(policy.get("id") or "")
            if not policy_id:
                continue
            rules = self._safe_list(f"{object_type}.rules", self.client.list_policy_rules, policy_id)
            yield RawObject(
                object_type=object_type,
                provider_id=policy_id,
                payload={**policy, "rules": rules},
                collected_at=now,
            )

    def _collect_access_policy(self, now: datetime) -> Iterable[RawObject]:
        yield from self._collect_policies_with_rules(now, "access_policy")

    def _collect_sign_on_policy(self, now: datetime) -> Iterable[RawObject]:
        yield from self._collect_policies_with_rules(now, "sign_on_policy")

    def _collect_profile_enrollment_policy(self, now: datetime) -> Iterable[RawObject]:
        yield from self._collect_policies_with_rules(now, "profile_enrollment_policy")

    def _collect_idp_discovery_policy(self, now: datetime) -> Iterable[RawObject]:
        yield from self._collect_policies_with_rules(now, "idp_discovery_policy")

    def _collect_authenticator(self, now: datetime) -> Iterable[RawObject]:
        for authenticator in self.client.list_authenticators():
            key = str(authenticator.get("key") or authenticator.get("id") or "")
            if not key:
                continue
            yield RawObject(
                object_type="authenticator",
                provider_id=key,
                payload=authenticator,
                collected_at=now,
            )

    def _collect_network_zone(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "network_zone", self.client.list_network_zones)

    def _collect_trusted_origin(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "trusted_origin", self.client.list_trusted_origins)

    def _collect_event_hook(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "event_hook", self.client.list_event_hooks, redact=_redact_hook)

    def _collect_inline_hook(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "inline_hook", self.client.list_inline_hooks, redact=_redact_hook)

    def _collect_identity_provider(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "identity_provider", self.client.list_identity_providers)

    def _collect_group_rule(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "group_rule", self.client.list_group_rules)

    def _simple_collect(
        self,
        now: datetime,
        object_type: str,
        fetch: Callable[[], list[dict[str, Any]]],
        *,
        redact: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> Iterable[RawObject]:
        """One RawObject per row, for families with no per-entity fan-out."""
        for row in fetch():
            provider_id = str(row.get("id") or "")
            if not provider_id:
                continue
            yield RawObject(
                object_type=object_type,
                provider_id=provider_id,
                payload=redact(row) if redact else row,
                collected_at=now,
            )

    def _collect_device_assurance_policy(self, now: datetime) -> Iterable[RawObject]:
        for policy in self.client.list_device_assurance_policies():
            policy_id = str(policy.get("id") or "")
            if not policy_id:
                continue
            yield RawObject(
                object_type="device_assurance_policy",
                provider_id=policy_id,
                payload=policy,
                collected_at=now,
            )

    def _collect_entity_risk_policy(self, now: datetime) -> Iterable[RawObject]:
        yield from self._collect_policies_with_rules(now, "entity_risk_policy")

    def _collect_post_auth_session_policy(self, now: datetime) -> Iterable[RawObject]:
        yield from self._collect_policies_with_rules(now, "post_auth_session_policy")

    # -- privilege model (extended) ----------------------------

    def _collect_iam_role(self, now: datetime) -> Iterable[RawObject]:
        """Custom IAM roles with their permission list attached.

        Permissions live on a sub-resource; attaching them here keeps the
        normalizer a pure mapping and avoids an extra fan-out in policies.
        """
        for role in self.client.list_iam_roles():
            role_id = str(role.get("id") or "")
            if not role_id:
                continue
            permissions = self._safe_list("iam_role.permissions", self.client.list_iam_role_permissions, role_id)
            payload = dict(role)
            payload["permissions"] = permissions
            yield RawObject(
                object_type="iam_role",
                provider_id=role_id,
                payload=payload,
                collected_at=now,
            )

    def _collect_resource_set(self, now: datetime) -> Iterable[RawObject]:
        yield from self._simple_collect(now, "resource_set", self.client.list_resource_sets)

    # -- security behaviors (extended) ------------------------

    def _collect_behavior(self, now: datetime) -> Iterable[RawObject]:
        """Okta behavioral detection rules.

        Each behavior (``anomalousLocation``, ``anomalousDevice``, etc.) has a
        ``status`` (ACTIVE / INACTIVE) and ``settings.evaluateOnSignIn``. A
        behavior that is INACTIVE or not evaluating on sign-in does not feed
        adaptive auth signals.
        """
        yield from self._simple_collect(now, "behavior", self.client.list_behaviors)

    # -- infrastructure (extended) ----------------------------

    def _collect_log_stream(self, now: datetime) -> Iterable[RawObject]:
        """External log forwarding destinations (Splunk, AWS EventBridge, etc.).

        An org with no ACTIVE log stream ships events to Okta's own log only.
        That satisfies compliance checkbox requirements but gives the security
        team no real-time signal.
        """
        yield from self._simple_collect(now, "log_stream", self.client.list_log_streams)

    def _collect_auth_server(self, now: datetime) -> Iterable[RawObject]:
        """Custom authorization servers with their policies and scopes attached.

        Access-token lifetimes and wildcard scopes live on the inner OAuth
        layer — not on the main Okta policy surface — so most posture tools
        miss them.
        """
        for server in self.client.list_authorization_servers():
            server_id = str(server.get("id") or "")
            if not server_id:
                continue
            policies = self._safe_list("auth_server.policies", self.client.list_auth_server_policies, server_id)
            scopes = self._safe_list("auth_server.scopes", self.client.list_auth_server_scopes, server_id)
            payload = dict(server)
            payload["policies"] = policies
            payload["scopes"] = scopes
            # Derive the longest access-token lifetime across all policies/rules
            # so the normalizer and policies can read it without re-deriving.
            payload["max_access_token_lifetime_minutes"] = _max_token_lifetime_minutes(policies)
            yield RawObject(
                object_type="auth_server",
                provider_id=server_id,
                payload=payload,
                collected_at=now,
            )

    # -- devices (extended) -----------------------------------

    def _collect_device(self, now: datetime) -> Iterable[RawObject]:
        """Enrolled Okta-managed devices with their user links.

        Requires ``okta.devices.read`` scope; degrades on SSWS tokens without
        Super Admin. Device status (ACTIVE / SUSPENDED) and managed flag feed
        the device-compromised / unencrypted posture checks.
        """
        for dev in self.client.list_devices():
            device_id = str(dev.get("id") or "")
            if not device_id:
                continue
            users = self._safe_list("device.users", self.client.list_device_users, device_id)
            payload = dict(dev)
            payload["linked_users"] = users
            yield RawObject(
                object_type="device",
                provider_id=device_id,
                payload=payload,
                collected_at=now,
            )


def _max_token_lifetime_minutes(policies: list[dict[str, Any]]) -> int | None:
    """Largest access-token lifetime (in minutes) across all auth-server policies.

    Okta stores ``accessTokenLifetimeMinutes`` on the policy itself (not rules).
    Zero or None means "not set on this policy".
    """
    lifetimes: list[int] = []
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        val = policy.get("accessTokenLifetimeMinutes") or policy.get("conditions", {}).get("accessTokenLifetimeMinutes")
        if isinstance(val, int) and val > 0:
            lifetimes.append(val)
        # Also scan rules for override lifetimes.
        for rule in policy.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            rule_actions = rule.get("actions") or {}
            rule_token = rule_actions.get("token") or {}
            rv = rule.get("accessTokenLifetimeMinutes") or rule_token.get("accessTokenLifetimeMinutes")
            if isinstance(rv, int) and rv > 0:
                lifetimes.append(rv)
    return max(lifetimes) if lifetimes else None


def _app_scopes(app: dict[str, Any]) -> list[str]:
    settings = sub_dict(app, "settings")
    oauth = sub_dict(settings, "oauthClient")
    grant_types = oauth.get("grant_types") or oauth.get("grantTypes") or []
    # Okta stores requested scopes under oauthClient.consent_method / redirect;
    # fixtures may put an explicit `scopes` list on the app or oauthClient.
    scopes = oauth.get("scopes") or app.get("scopes") or []
    if isinstance(scopes, str):
        scopes = [s.strip() for s in scopes.split() if s.strip()]
    out = [str(s) for s in scopes]
    # Surface grant types as coarse scope signals when scopes list is empty.
    if not out and isinstance(grant_types, list):
        out = [f"grant:{g}" for g in grant_types]
    return out


def _is_service_app(app: dict[str, Any]) -> bool:
    """An OIDC app that authenticates as itself (client credentials) rather
    than on behalf of a user: an API service integration."""
    settings = sub_dict(app, "settings")
    oauth = sub_dict(settings, "oauthClient")
    if str(oauth.get("application_type") or oauth.get("applicationType") or "").lower() == "service":
        return True
    grant_types = oauth.get("grant_types") or oauth.get("grantTypes") or []
    return isinstance(grant_types, list) and "client_credentials" in grant_types
