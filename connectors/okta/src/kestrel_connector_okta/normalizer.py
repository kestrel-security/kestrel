# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Maps Okta RawObjects into Kestrel NormalizedObjects."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.activity_actions import category_for
from kestrel.connectors.sdk.base import NormalizedObject, NormalizedRelationship, RawObject
from kestrel.connectors.sdk.payload import classify_worker_type, looks_like_email, sub_dict
from kestrel.connectors.settings_emit import setting_object, settings_from_mapping

_SENSITIVE_SCOPES = frozenset(
    {
        "okta.users.manage",
        "okta.users.read",
        "okta.groups.manage",
        "okta.apps.manage",
        "okta.roles.manage",
        "openid",
        "profile",
        "email",
        "offline_access",
        "okta.myAccount.manage",
    }
)

_ORG_SETTING_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "subdomain",
        "workspace",
        "Okta subdomain",
        "string",
        "Okta org subdomain (tenant slug).",
    ),
    (
        "password_min_length",
        "security",
        "Password minimum length",
        "number",
        "Minimum password length from the active Okta password policy.",
    ),
    (
        "password_complexity",
        "security",
        "Password complexity requirements",
        "object",
        "Password complexity rules from the Okta password policy.",
    ),
    (
        "threat_insight_enabled",
        "security",
        "Threat Insight enabled",
        "boolean",
        "Whether Okta Threat Insight is enabled for the org.",
    ),
    (
        "mfa_enroll_policy_required",
        "security",
        "MFA enrollment policy requires a factor",
        "boolean",
        "True when an active MFA_ENROLL policy requires at least one authenticator.",
    ),
]

# Curated System Log eventType → Kestrel activity action.
# Expanded from ~16 to ~100 mappings in extended; unmapped types are dropped.
# Login-success noise is intentionally omitted.
# Use category_for() at normalize time rather than a local dict so the
# vocabulary stays in sync with activity_actions.py.

_OKTA_EVENT_TO_KESTREL: dict[str, str] = {
    # ---- privilege / access ----
    "user.account.privilege.grant": "privilege.grant",
    "group.privilege.grant": "privilege.grant",
    "application.privilege.grant": "privilege.grant",
    "user.account.privilege.revoke": "privilege.revoke",
    "group.privilege.revoke": "privilege.revoke",
    # IAM custom roles
    "iam.role.member.add": "privilege.grant",
    "iam.role.member.remove": "privilege.revoke",
    "iam.role.permission.granted": "privilege.grant",
    "iam.role.permission.revoked": "privilege.revoke",
    "iam.resourceset.binding.add": "privilege.grant",
    "iam.resourceset.binding.remove": "privilege.revoke",
    # Group member changes that affect privilege
    "group.user_membership.add": "group.member.add",
    "group.user_membership.remove": "group.member.remove",
    # ---- MFA ----
    "user.mfa.factor.deactivate": "mfa.disable",
    "user.mfa.factor.reset_all": "mfa.disable",
    "user.mfa.factor.deactivate_all": "mfa.disable",
    "system.mfa.factor.deactivate": "mfa.disable",
    "user.mfa.factor.activate": "mfa.enable",
    "user.mfa.factor.update": "mfa.enable",
    "user.mfa.okta_verify.enrolled": "mfa.enable",
    "user.mfa.okta_verify.deactivated": "mfa.disable",
    # Authenticator lifecycle
    "security.authenticator.lifecycle.activated": "mfa.enable",
    "security.authenticator.lifecycle.deactivated": "mfa.disable",
    "security.authenticator.lifecycle.created": "config.change",
    "security.authenticator.lifecycle.deleted": "config.change",
    # ---- threats / risk ----
    "security.threat.detected": "threat.detected",
    "security.attack.start": "threat.detected",
    "user.risk.detect": "threat.detected",
    "security.request.blocked": "threat.detected",
    # ---- auth / session ----
    "user.session.access_admin_app": "admin.console",
    "user.session.impersonation.initiate": "admin.console",
    "user.session.impersonation.grant": "privilege.grant",
    "user.session.impersonation.extend": "admin.console",
    "user.session.impersonation.end": "privilege.revoke",
    # ---- identity lifecycle ----
    "user.lifecycle.create": "identity.add",
    "user.lifecycle.create.initiate": "identity.add",
    "user.lifecycle.activate": "identity.add",
    "user.lifecycle.reactivate": "dormant.reactivate",
    "user.lifecycle.deactivate": "identity.deactivate",
    "user.lifecycle.suspend": "identity.deactivate",
    "user.lifecycle.unsuspend": "dormant.reactivate",
    "user.lifecycle.delete.completed": "identity.deactivate",
    # ---- credentials ----
    "user.account.reset_password": "credential.change",
    "user.account.unlock": "credential.change",
    "user.account.update_password": "credential.change",
    "user.account.lock": "identity.deactivate",
    # API tokens
    "api.token.create": "api.token.create",
    "system.api_token.create": "api.token.create",
    "system.api_token.revoke": "credential.change",
    "system.api_token.delete": "credential.change",
    # ---- OAuth / apps ----
    "app.oauth2.as.consent.grant": "token.grant",
    "app.oauth2.as.consent.revoke": "oauth.app.revoke",
    "app.oauth2.token.grant": "token.grant",
    "app.oauth2.token.revoke": "oauth.app.revoke",
    "app.oauth2.scope.consent.granted": "oauth.sensitive_consent",
    "app.oauth2.scope.consent.denied": "oauth.sensitive_consent",
    # App lifecycle
    "app.lifecycle.create": "oauth.app.install",
    "app.lifecycle.activate": "oauth.app.install",
    "app.lifecycle.deactivate": "oauth.app.revoke",
    "app.lifecycle.delete": "oauth.app.revoke",
    "app.lifecycle.update": "config.change",
    # App sign-on policy changes
    "application.policy.sign_on.update": "sso.change",
    # ---- policy changes ----
    "policy.lifecycle.create": "policy.change",
    "policy.lifecycle.update": "policy.change",
    "policy.lifecycle.delete": "policy.change",
    "policy.lifecycle.activate": "policy.change",
    "policy.lifecycle.deactivate": "policy.change",
    "policy.rule.add": "policy.change",
    "policy.rule.update": "policy.change",
    "policy.rule.delete": "policy.change",
    "policy.rule.activate": "policy.change",
    "policy.rule.deactivate": "policy.change",
    # ---- network zone changes ----
    "zone.create": "config.change",
    "zone.update": "config.change",
    "zone.delete": "config.change",
    "zone.activate": "config.change",
    "zone.deactivate": "config.change",
    # ---- IdP / SSO ----
    "system.idp.lifecycle.create": "sso.change",
    "system.idp.lifecycle.activate": "sso.change",
    "system.idp.lifecycle.deactivate": "sso.change",
    "system.idp.lifecycle.delete": "sso.change",
    "system.idp.lifecycle.update": "sso.change",
    # ---- hooks ----
    "event_hook.create": "webhook.create",
    "event_hook.update": "config.change",
    "event_hook.delete": "config.change",
    "event_hook.activate": "config.change",
    "event_hook.deactivate": "config.change",
    "inline_hook.create": "webhook.create",
    "inline_hook.update": "config.change",
    "inline_hook.delete": "config.change",
    # ---- log streams ----
    "system.log_stream.create": "config.change",
    "system.log_stream.update": "config.change",
    "system.log_stream.delete": "config.change",
    "system.log_stream.activate": "config.change",
    "system.log_stream.deactivate": "config.change",
    # ---- devices ----
    "device.enrollment.create": "device.enroll",
    "device.enrollment.update": "device.enroll",
    "device.enrollment.delete": "device.wipe",
    "device.lifecycle.activate": "device.enroll",
    "device.lifecycle.deactivate": "device.wipe",
    "device.lifecycle.suspend": "device.compliance_fail",
    "device.assurance.create": "config.change",
    "device.assurance.update": "config.change",
    "device.assurance.delete": "config.change",
    # ---- support access ----
    "user.support.access.granted": "support.access",
    "user.support.access.revoked": "support.access",
}


_SIGN_ON_MODE_KINDS: dict[str, str] = {
    "SAML_2_0": "saml",
    "SAML_1_1": "saml",
    "WS_FEDERATION": "wsfed",
    "OPENID_CONNECT": "oidc",
    "BROWSER_PLUGIN": "swa",
    "SECURE_PASSWORD_STORE": "swa",
    "AUTO_LOGIN": "swa",
    "BASIC_AUTH": "swa",
    "BOOKMARK": "bookmark",
}


def _app_kind(sign_on_mode: str, *, is_service: bool) -> str:
    if is_service:
        return "service"
    return _SIGN_ON_MODE_KINDS.get(sign_on_mode.upper(), "unknown")


def _is_sensitive_scope(scope_name: str) -> bool:
    return scope_name in _SENSITIVE_SCOPES or scope_name.startswith("okta.")


def _profile(user: dict[str, Any]) -> dict[str, Any]:
    profile = user.get("profile")
    return profile if isinstance(profile, dict) else {}


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _password_policy_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings = sub_dict(payload, "settings")
    password = sub_dict(settings, "password")
    complexity = sub_dict(password, "complexity")
    out: dict[str, Any] = {}
    min_length = complexity.get("minLength") or complexity.get("min_length")
    if min_length is not None:
        out["password_min_length"] = int(min_length)
    if complexity:
        out["password_complexity"] = {
            "minLength": complexity.get("minLength"),
            "minLowerCase": complexity.get("minLowerCase"),
            "minUpperCase": complexity.get("minUpperCase"),
            "minNumber": complexity.get("minNumber"),
            "minSymbol": complexity.get("minSymbol"),
            "excludeUsername": complexity.get("excludeUsername"),
        }
    return out


def _threat_insight_enabled(payload: dict[str, Any]) -> bool | None:
    action = payload.get("action")
    if action is None:
        return None
    return str(action).lower() not in {"none", "disabled", "off"}


def _mfa_enroll_policy_required(payload: dict[str, Any]) -> bool | None:
    """True when an ACTIVE MFA_ENROLL policy requires at least one factor."""
    if str(payload.get("status") or "").upper() != "ACTIVE":
        return False
    settings = sub_dict(payload, "settings")
    factors = sub_dict(settings, "factors")
    if not factors:
        return None
    for spec in factors.values():
        if not isinstance(spec, dict):
            continue
        enroll = sub_dict(spec, "enroll")
        if str(enroll.get("self") or "").upper() == "REQUIRED":
            return True
    return False


class OktaNormalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        method = getattr(self, f"_normalize_{object_type}", None)
        if method is None:
            raise ValueError(f"OktaNormalizer does not support object_type '{object_type}'")
        return method(raw)

    def _normalize_org(self, raw: RawObject) -> list[NormalizedObject]:
        """Org identity only.

        `GET /api/v1/org` is the Org Settings resource: company name, contact,
        address, status. It carries no security configuration. A previous
        version derived `mfa_enroll_required` from it with a `setdefault` whose
        fallback was `bool(None or None)`, so every live tenant got a confident
        `False` for a field Okta never returned -- and a high-severity finding
        with it. MFA enrollment is read from the MFA_ENROLL policy instead; see
        `_normalize_mfa_enroll_policy`.
        """
        payload = dict(raw.payload)
        payload.setdefault("subdomain", payload.get("subdomain") or payload.get("companyName"))
        return settings_from_mapping(payload, _ORG_SETTING_SPECS, provider_id_prefix="org-setting")

    def _normalize_user(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        profile = _profile(payload)
        status = str(payload.get("status") or "").upper()
        is_disabled = status in {"DEPROVISIONED", "SUSPENDED"}
        email = profile.get("email") or profile.get("login")
        # Okta service accounts often use @clients.okta.com or no human name.
        identity_type = "user"
        if profile.get("login") and str(profile.get("login")).endswith("@clients.okta.com"):
            identity_type = "service_account"
        # `userType` is a free-text profile attribute; `isExternal` is the
        # Okta-managed flag. Either marks a contingent worker, and a tenant
        # that fills in neither gets `unknown`, never `employee`.
        user_type = profile.get("userType")
        worker_type = classify_worker_type(user_type, is_bot=identity_type == "service_account")
        if worker_type == "unknown" and profile.get("isExternal"):
            worker_type = "contractor"
        manager_email = looks_like_email(profile.get("managerId")) or looks_like_email(profile.get("manager"))
        return [
            NormalizedObject(
                kind="identity",
                provider_id=raw.provider_id,
                attributes={
                    "identity_type": identity_type,
                    "display_name": (
                        " ".join(p for p in (profile.get("firstName"), profile.get("lastName")) if p).strip()
                        or profile.get("displayName")
                        or profile.get("login")
                        or raw.provider_id
                    ),
                    "email": email,
                    "is_disabled": is_disabled,
                    "is_external": bool(profile.get("userType") == "Contractor" or profile.get("isExternal")),
                    "mfa_enabled": payload.get("mfa_enabled"),
                    "last_active_at": _parse_dt(payload.get("lastLogin")),
                    "last_active_source": "login" if payload.get("lastLogin") else None,
                    "created_at_source": _parse_dt(payload.get("created")),
                    "worker_type": worker_type,
                    "department": profile.get("department") or None,
                    "title": profile.get("title") or None,
                    "manager_email": manager_email,
                    # `statusChanged` moves on every lifecycle transition; it is
                    # "when disabled" only while the account is disabled.
                    "disabled_at": _parse_dt(payload.get("statusChanged")) if is_disabled else None,
                    "user_type": user_type or None,
                    "status": status or None,
                    "employee_number": profile.get("employeeNumber") or None,
                    "organization": profile.get("organization") or None,
                    "manager_ref": None if manager_email else (profile.get("managerId") or profile.get("manager") or None),
                },
                raw_source=payload,
            )
        ]

    def _normalize_group(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        profile = sub_dict(payload, "profile")
        return [
            NormalizedObject(
                kind="group",
                provider_id=raw.provider_id,
                attributes={
                    "name": profile.get("name") or payload.get("name") or raw.provider_id,
                    "description": profile.get("description"),
                },
                raw_source=payload,
            )
        ]

    def _normalize_group_member(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        group_id = str(payload["group_id"])
        identity_id = str(payload["user_id"])
        return [
            NormalizedObject(
                kind="group_membership",
                provider_id=raw.provider_id,
                attributes={"group_ref": group_id, "identity_ref": identity_id},
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="member_of",
                        source_ref=identity_id,
                        target_ref=group_id,
                        access_path="direct",
                    )
                ],
            )
        ]

    def _normalize_admin_role(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="role",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload["name"],
                    "is_privileged": bool(payload.get("is_privileged", False)),
                },
                raw_source=payload,
            )
        ]

    def _normalize_role_assignment(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        role_id = str(payload["role_id"])
        identity_id = str(payload["user_id"])
        assignment_type = str(payload.get("assignment_type") or "USER").upper()
        group_id = payload.get("group_id")
        via_group = assignment_type == "GROUP" and bool(group_id)
        attrs: dict[str, Any] = {
            "granted_via": "group" if via_group else "direct",
            "identity_ref": identity_id,
            "role_ref": role_id,
        }
        if via_group:
            attrs["source_group_ref"] = str(group_id)
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes=attrs,
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role",
                        source_ref=identity_id,
                        target_ref=role_id,
                        access_path="inherited_group" if via_group else "direct",
                    )
                ],
            )
        ]

    def _normalize_app(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        sign_on_mode = str(payload.get("signOnMode") or "")
        settings = sub_dict(payload, "settings")
        oauth = sub_dict(settings, "oauthClient")
        grant_types = oauth.get("grant_types") or oauth.get("grantTypes") or []
        is_service = str(oauth.get("application_type") or "").lower() == "service" or (
            isinstance(grant_types, list) and "client_credentials" in grant_types
        )
        return [
            NormalizedObject(
                kind="oauth_application",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload.get("label") or payload.get("name") or raw.provider_id,
                    "publisher": payload.get("createdBy") or "okta",
                    "is_verified": str(payload.get("status") or "").upper() == "ACTIVE",
                    "owner_identity_ref": None,
                    # Every Okta app lands as an oauth_application row; the kind
                    # says what it actually is so Explore and policies can tell
                    # a SAML SSO tile from an API service integration.
                    "app_kind": _app_kind(sign_on_mode, is_service=is_service),
                    "sign_on_mode": sign_on_mode,
                    "is_service_app": is_service,
                    "status": payload.get("status"),
                },
                raw_source=payload,
            )
        ]

    def _normalize_app_scope(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        scope_name = str(payload["scope_name"])
        return [
            NormalizedObject(
                kind="oauth_scope",
                provider_id=raw.provider_id,
                attributes={
                    "oauth_application_ref": str(payload["app_id"]),
                    "scope_name": scope_name,
                    "is_sensitive": _is_sensitive_scope(scope_name),
                },
                raw_source=payload,
            )
        ]

    def _normalize_app_group(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        app_id = str(payload["app_id"])
        group_id = str(payload["group_id"])
        return [
            NormalizedObject(
                kind="oauth_grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "group",
                    "source_group_ref": group_id,
                    "oauth_application_ref": app_id,
                    "identity_ref": None,
                    "permission_level": "assigned",
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="can_access",
                        source_ref=group_id,
                        target_ref=app_id,
                        access_path="direct",
                    )
                ],
            )
        ]

    def _normalize_app_user(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        app_id = str(payload["app_id"])
        identity_id = str(payload["user_id"])
        return [
            NormalizedObject(
                kind="oauth_grant",
                provider_id=raw.provider_id,
                attributes={
                    "oauth_application_ref": app_id,
                    "identity_ref": identity_id,
                    "granted_at": payload.get("created") or payload.get("lastUpdated"),
                    "last_used_at": payload.get("lastUpdated") if payload.get("status") == "ACTIVE" else None,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="possesses_scope",
                        source_ref=identity_id,
                        target_ref=app_id,
                        access_path="oauth_derived",
                    )
                ],
            )
        ]

    def _normalize_password_policy(self, raw: RawObject) -> list[NormalizedObject]:
        mapped = _password_policy_settings(raw.payload)
        return settings_from_mapping(mapped, _ORG_SETTING_SPECS, provider_id_prefix="password-policy")

    def _normalize_mfa_enroll_policy(self, raw: RawObject) -> list[NormalizedObject]:
        required = _mfa_enroll_policy_required(raw.payload)
        if required is None:
            return []
        return settings_from_mapping(
            {"mfa_enroll_policy_required": required},
            _ORG_SETTING_SPECS,
            provider_id_prefix="mfa-enroll-policy",
        )

    def _normalize_threat_insight(self, raw: RawObject) -> list[NormalizedObject]:
        enabled = _threat_insight_enabled(raw.payload)
        if enabled is None:
            return []
        return settings_from_mapping(
            {"threat_insight_enabled": enabled},
            _ORG_SETTING_SPECS,
            provider_id_prefix="org-setting",
        )

    def _normalize_api_token(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        name = str(payload.get("name") or raw.provider_id)
        user_id = payload.get("userId")
        display = f"API token: {name}"
        if user_id:
            display = f"{display} (user {user_id})"
        return [
            NormalizedObject(
                kind="identity",
                provider_id=f"api-token:{raw.provider_id}",
                attributes={
                    "identity_type": "service_account",
                    "display_name": display,
                    "email": None,
                    "is_disabled": False,
                    "mfa_enabled": None,
                    "is_external": False,
                    # `lastUpdated` is when the token record changed, not when
                    # it was used; labelled so dormancy checks do not trust it.
                    "last_active_at": _parse_dt(payload.get("lastUpdated")),
                    "last_active_source": "profile" if payload.get("lastUpdated") else None,
                    "created_at_source": _parse_dt(payload.get("created")),
                    "worker_type": "service",
                    # The user the token was issued to is its owner.
                    "owner_identity_ref": str(user_id) if user_id else None,
                },
                raw_source=payload,
            )
        ]

    def _normalize_app_sign_on_setting(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        app_id = str(payload.get("app_id") or raw.provider_id)
        sign_on_mode = str(payload.get("signOnMode") or "")
        name = str(payload.get("name") or app_id)
        key = f"okta_app_sign_on_mode:{app_id}"
        return [
            setting_object(
                key=key,
                category="access",
                label=f"App sign-on mode ({name})",
                value={
                    "app_id": app_id,
                    "name": name,
                    "sign_on_mode": sign_on_mode,
                    "status": payload.get("status"),
                },
                value_type="object",
                description="Okta application sign-on mode (SSO vs bookmark/SWA).",
                raw_source=payload,
                provider_id_prefix="app-setting",
            )
        ]

    # -- authentication and session policy surface ----------------

    def _normalize_access_policy(self, raw: RawObject) -> list[NormalizedObject]:
        return _policy_rule_settings(raw, "access-policy", "Authentication policy")

    def _normalize_sign_on_policy(self, raw: RawObject) -> list[NormalizedObject]:
        return _policy_rule_settings(raw, "sign-on-policy", "Global session policy")

    def _normalize_profile_enrollment_policy(self, raw: RawObject) -> list[NormalizedObject]:
        return _policy_rule_settings(raw, "profile-enrollment-policy", "Profile enrollment policy")

    def _normalize_idp_discovery_policy(self, raw: RawObject) -> list[NormalizedObject]:
        return _policy_rule_settings(raw, "idp-discovery-policy", "Identity provider routing policy")

    def _normalize_authenticator(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        key = str(payload.get("key") or raw.provider_id)
        return [
            setting_object(
                key=f"okta_authenticator:{key}",
                category="security",
                label=f"Authenticator: {payload.get('name') or key}",
                value={
                    "key": key,
                    "type": payload.get("type"),
                    "status": payload.get("status"),
                    "phishing_resistant": key in _PHISHING_RESISTANT_AUTHENTICATORS,
                },
                value_type="object",
                description=(
                    "An enrolled authenticator type. Push and OTP factors are phishable; WebAuthn and smart cards are not."
                ),
                raw_source=payload,
                provider_id_prefix="authenticator",
            )
        ]

    def _normalize_device_assurance_policy(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            setting_object(
                key=f"okta_device_assurance:{raw.provider_id}",
                category="security",
                label=f"Device assurance policy: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "platform": payload.get("platform"),
                    "disk_encryption": bool(payload.get("diskEncryptionType")),
                    "screen_lock": bool(payload.get("screenLockType")),
                    "secure_hardware": payload.get("secureHardwarePresent"),
                },
                value_type="object",
                description="Device posture requirements available to authentication policy rules.",
                raw_source=payload,
                provider_id_prefix="device-assurance",
            )
        ]

    # -- perimeter and automation surface -------------------------

    def _normalize_network_zone(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        gateways = _zone_entries(payload.get("gateways"))
        proxies = _zone_entries(payload.get("proxies"))
        return [
            setting_object(
                key=f"okta_network_zone:{raw.provider_id}",
                category="access",
                label=f"Network zone: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "type": payload.get("type"),
                    "usage": payload.get("usage"),
                    "status": payload.get("status"),
                    "gateways": gateways,
                    "proxies": proxies,
                    # A policy zone that admits everything is the same as no
                    # zone at all, while looking like a control in the UI.
                    "matches_everything": _matches_everything(gateways),
                },
                value_type="object",
                description="A network zone referenced by policy rules to allow or block sign-in.",
                raw_source=payload,
                provider_id_prefix="network-zone",
            )
        ]

    def _normalize_trusted_origin(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        scopes = [
            str(scope.get("type")) for scope in payload.get("scopes") or [] if isinstance(scope, dict) and scope.get("type")
        ]
        origin = str(payload.get("origin") or "")
        return [
            setting_object(
                key=f"okta_trusted_origin:{raw.provider_id}",
                category="access",
                label=f"Trusted origin: {payload.get('name') or origin}",
                value={
                    "name": payload.get("name"),
                    "origin": origin,
                    "scopes": scopes,
                    "status": payload.get("status"),
                    # A redirect-scoped origin can receive a token, so plain
                    # HTTP there puts one on the wire in cleartext.
                    "insecure_scheme": origin.startswith("http://"),
                },
                value_type="object",
                description=(
                    "An origin allowed to make cross-origin calls or receive "
                    "redirects. A redirect origin can receive a token."
                ),
                raw_source=payload,
                provider_id_prefix="trusted-origin",
            )
        ]

    def _normalize_event_hook(self, raw: RawObject) -> list[NormalizedObject]:
        return [_hook_setting(raw, "event", "Event hook")]

    def _normalize_inline_hook(self, raw: RawObject) -> list[NormalizedObject]:
        return [_hook_setting(raw, "inline", "Inline hook")]

    def _normalize_identity_provider(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        policy = payload.get("policy") or {}
        provisioning = policy.get("provisioning") if isinstance(policy, dict) else None
        provisioning = provisioning if isinstance(provisioning, dict) else {}
        return [
            setting_object(
                key=f"okta_identity_provider:{raw.provider_id}",
                category="access",
                label=f"Identity provider: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "type": payload.get("type"),
                    "status": payload.get("status"),
                    "provisioning_action": provisioning.get("action"),
                    # JIT provisioning means a successful assertion from this
                    # IdP creates an Okta account that did not exist before.
                    "auto_provisions_users": str(provisioning.get("action") or "").upper() == "AUTO",
                },
                value_type="object",
                description=("Inbound federation. Whoever operates this provider can assert identities into the org."),
                raw_source=payload,
                provider_id_prefix="identity-provider",
            )
        ]

    def _normalize_group_rule(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        conditions = payload.get("conditions") or {}
        expression = conditions.get("expression") if isinstance(conditions, dict) else None
        actions = payload.get("actions") or {}
        assign = actions.get("assignUserToGroups") if isinstance(actions, dict) else None
        group_ids = assign.get("groupIds") if isinstance(assign, dict) else None
        return [
            setting_object(
                key=f"okta_group_rule:{raw.provider_id}",
                category="access",
                label=f"Group rule: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "status": payload.get("status"),
                    "expression": (expression.get("value") if isinstance(expression, dict) else None),
                    "assigns_to_group_ids": list(group_ids or []),
                },
                value_type="object",
                description=(
                    "Dynamic group membership. A rule targeting a privileged "
                    "group turns a profile attribute into a privilege grant."
                ),
                raw_source=payload,
                provider_id_prefix="group-rule",
            )
        ]

    def _normalize_system_log(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        action = _kestrel_action_for_okta_event(payload)
        if action is None:
            return []
        actor = sub_dict(payload, "actor")
        target = _first_user_target(payload)
        occurred_at = payload.get("published") or payload.get("occurred_at")
        event_type = str(payload.get("eventType") or action)
        display = payload.get("displayMessage") or event_type
        return [
            NormalizedObject(
                kind="event",
                provider_id=raw.provider_id,
                attributes={
                    "action": action,
                    "action_category": category_for(action),
                    "actor_email": actor.get("alternateId") or actor.get("displayName"),
                    "actor_provider_id": str(actor["id"]) if actor.get("id") else None,
                    "target_email": target.get("alternateId") if target else None,
                    "target_type": "identity" if target else None,
                    "target_provider_id": str(target["id"]) if target and target.get("id") else None,
                    "occurred_at": occurred_at,
                    "summary": f"Okta System Log: {display} ({action})",
                    "attributes": {
                        "okta_event_type": event_type,
                        "severity": payload.get("severity"),
                        "outcome": (payload.get("outcome") or {}).get("result")
                        if isinstance(payload.get("outcome"), dict)
                        else None,
                    },
                },
                raw_source=payload,
            )
        ]

    # -- extended normalizers ----------------------------------------

    def _normalize_entity_risk_policy(self, raw: RawObject) -> list[NormalizedObject]:
        return _policy_rule_settings(raw, "entity-risk-policy", "Entity risk policy")

    def _normalize_post_auth_session_policy(self, raw: RawObject) -> list[NormalizedObject]:
        return _policy_rule_settings(raw, "post-auth-session-policy", "Post-auth session policy")

    def _normalize_iam_role(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        permissions = [
            str(p.get("type") or p.get("label") or p.get("value") or "")
            for p in (payload.get("permissions") or [])
            if isinstance(p, dict)
        ]
        # An org-wide custom role has no resource set bindings — it applies to
        # every resource of its type, making it equivalent to a classic ORG_ADMIN.
        return [
            NormalizedObject(
                kind="role",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload.get("label") or payload.get("name") or raw.provider_id,
                    "is_privileged": True,
                    "description": payload.get("description"),
                    "role_type": "custom_iam",
                    "permissions": permissions,
                    "permission_count": len(permissions),
                    "is_super_admin_equivalent": any("super" in str(p).lower() for p in permissions),
                },
                raw_source=payload,
            )
        ]

    def _normalize_resource_set(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            setting_object(
                key=f"okta_resource_set:{raw.provider_id}",
                category="access",
                label=f"IAM resource set: {payload.get('label') or raw.provider_id}",
                value={
                    "label": payload.get("label"),
                    "description": payload.get("description"),
                },
                value_type="object",
                description=(
                    "Resource sets scope a custom IAM role to a subset of the directory "
                    "(e.g., a specific group of users). Without resource-set constraints, "
                    "a custom role applies org-wide."
                ),
                raw_source=payload,
                provider_id_prefix="resource-set",
            )
        ]

    def _normalize_behavior(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        settings = payload.get("settings") or {}
        evaluate_on_sign_in = bool(settings.get("evaluateOnSignIn")) if isinstance(settings, dict) else None
        return [
            setting_object(
                key=f"okta_behavior:{raw.provider_id}",
                category="security",
                label=f"Behavior detection: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "type": payload.get("type"),
                    "status": payload.get("status"),
                    "evaluate_on_sign_in": evaluate_on_sign_in,
                    "is_active": str(payload.get("status") or "").upper() == "ACTIVE",
                    # A behavior that is ACTIVE but not evaluating on sign-in
                    # provides no runtime signal.
                    "effective": (str(payload.get("status") or "").upper() == "ACTIVE" and bool(evaluate_on_sign_in)),
                },
                value_type="object",
                description=(
                    "A behavioral detection rule feeding Okta's risk engine. "
                    "Disabled behaviors (INACTIVE or evaluateOnSignIn=false) "
                    "do not surface anomalous location, device, or IP signals."
                ),
                raw_source=payload,
                provider_id_prefix="behavior",
            )
        ]

    def _normalize_log_stream(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        settings = payload.get("settings") or {}
        return [
            setting_object(
                key=f"okta_log_stream:{raw.provider_id}",
                category="security",
                label=f"Log stream: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "type": payload.get("type"),
                    "status": payload.get("status"),
                    "is_active": str(payload.get("status") or "").upper() == "ACTIVE",
                    "destination": str(settings.get("bucket") or settings.get("indexName") or settings.get("host") or ""),
                },
                value_type="object",
                description=(
                    "An external log forwarding destination. An org with no active "
                    "log stream ships events to Okta's own log only, giving the "
                    "security team no real-time signal in their SIEM."
                ),
                raw_source=payload,
                provider_id_prefix="log-stream",
            )
        ]

    def _normalize_auth_server(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        scopes = payload.get("scopes") or []
        has_wildcard_scope = any(
            str(s.get("name") or "").strip() in {"*", ".*"} or str(s.get("name") or "").endswith(":*")
            for s in scopes
            if isinstance(s, dict)
        )
        policies = payload.get("policies") or []
        max_lifetime = payload.get("max_access_token_lifetime_minutes")
        return [
            setting_object(
                key=f"okta_auth_server:{raw.provider_id}",
                category="security",
                label=f"Authorization server: {payload.get('name') or raw.provider_id}",
                value={
                    "name": payload.get("name"),
                    "description": payload.get("description"),
                    "audiences": payload.get("audiences") or [],
                    "issuer": payload.get("issuer"),
                    "status": payload.get("status"),
                    "is_default": bool(payload.get("name") == "default"),
                    "scope_count": len(scopes),
                    "policy_count": len(policies),
                    "max_access_token_lifetime_minutes": max_lifetime,
                    # Tokens older than 1 hour risk long-lived access after
                    # account disable, because the token remains valid until it
                    # expires even when the user is deprovisioned.
                    "token_lifetime_excessive": isinstance(max_lifetime, int) and max_lifetime > 60,
                    "has_wildcard_scope": has_wildcard_scope,
                },
                value_type="object",
                description=(
                    "A custom OAuth 2.0 authorization server. Access-token lifetimes "
                    "and wildcard scopes here are missed by most posture tools."
                ),
                raw_source=payload,
                provider_id_prefix="auth-server",
            )
        ]

    def _normalize_device(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        profile = payload.get("profile") or {}
        management = payload.get("resourceType") or payload.get("managementType") or "unknown"
        linked_users = payload.get("linked_users") or []
        user_ids = [str(u.get("user", {}).get("id") or u.get("id") or "") for u in linked_users if isinstance(u, dict)]
        return [
            NormalizedObject(
                kind="resource",
                provider_id=raw.provider_id,
                attributes={
                    "resource_type": "device",
                    "name": (profile.get("displayName") or profile.get("serialNumber") or raw.provider_id),
                    "status": payload.get("status"),
                    "is_managed": bool(payload.get("managed") or management.lower() not in {"", "unknown", "unmanaged"}),
                    "platform": profile.get("platform"),
                    "os_version": profile.get("osVersion"),
                    "serial_number": profile.get("serialNumber"),
                    "disk_encrypted": profile.get("diskEncryptionType") not in {None, "NONE", ""},
                    "linked_user_ids": user_ids,
                },
                raw_source=payload,
            )
        ]


def _first_user_target(payload: dict[str, Any]) -> dict[str, Any] | None:
    targets = payload.get("target")
    if not isinstance(targets, list):
        return None
    for row in targets:
        if isinstance(row, dict) and str(row.get("type") or "").lower() in {"user", "appuser"}:
            return row
    for row in targets:
        if isinstance(row, dict):
            return row
    return None


def _kestrel_action_for_okta_event(payload: dict[str, Any]) -> str | None:
    event_type = payload.get("eventType")
    if isinstance(event_type, str) and event_type in _OKTA_EVENT_TO_KESTREL:
        return _OKTA_EVENT_TO_KESTREL[event_type]
    return None


# -- authentication and session policy surface ---------------------

# Authenticator keys that resist phishing because the credential is bound to
# the origin. Push and OTP are deliberately absent: both can be relayed by an
# attacker-in-the-middle proxy, which is how most MFA bypass actually happens.
_PHISHING_RESISTANT_AUTHENTICATORS = frozenset({"webauthn", "smart_card_idp", "fido2"})

# Factor prompt modes that mean "no second factor on this rule".
_NO_MFA_PROMPT_MODES = frozenset({"NEVER", "DISABLED"})


def _rule_session(rule: dict[str, Any]) -> dict[str, Any]:
    """Session controls from a rule's sign-on action.

    Okta expresses lifetime and idle timeout in minutes, with **0 meaning
    unlimited** -- so a rule that reads like a tight timeout may have none at
    all. That inversion is why this is summarized rather than passed through.
    """
    actions = rule.get("actions") or {}
    signon = actions.get("signon") if isinstance(actions, dict) else None
    session = signon.get("session") if isinstance(signon, dict) else None
    if not isinstance(session, dict):
        return {}
    lifetime = session.get("maxSessionLifetimeMinutes")
    idle = session.get("maxSessionIdleMinutes")
    return {
        "max_session_lifetime_minutes": lifetime,
        "max_session_idle_minutes": idle,
        "unlimited_lifetime": lifetime == 0,
        "unlimited_idle": idle == 0,
        "persistent_cookie": session.get("usePersistentCookie"),
    }


def _rule_requires_mfa(rule: dict[str, Any]) -> bool | None:
    """Whether a rule demands a second factor. None when it says nothing."""
    actions = rule.get("actions") or {}
    signon = actions.get("signon") if isinstance(actions, dict) else None
    if not isinstance(signon, dict):
        return None
    requirement = signon.get("requireFactor")
    if isinstance(requirement, bool):
        return requirement
    prompt = str(signon.get("factorPromptMode") or "").upper()
    if not prompt:
        return None
    return prompt not in _NO_MFA_PROMPT_MODES


def _rule_network(rule: dict[str, Any]) -> dict[str, Any]:
    conditions = rule.get("conditions") or {}
    network = conditions.get("network") if isinstance(conditions, dict) else None
    if not isinstance(network, dict):
        return {}
    return {
        "connection": network.get("connection"),
        "zones_included": network.get("include") or [],
        "zones_excluded": network.get("exclude") or [],
    }


def _rule_self_service_registration(rule: dict[str, Any]) -> bool | None:
    """Whether a profile-enrollment rule lets anyone create an account.

    Only meaningful on PROFILE_ENROLLMENT policies; None everywhere else, so a
    policy author can tell "not applicable" from "explicitly disabled".
    """
    actions = rule.get("actions") or {}
    enrollment = actions.get("profileEnrollment") if isinstance(actions, dict) else None
    if not isinstance(enrollment, dict):
        return None
    raw = enrollment.get("selfServiceRegistration")
    if raw is None:
        return None
    return str(raw).upper() == "ENABLED"


def _summarize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "status": rule.get("status"),
        "priority": rule.get("priority"),
        "requires_mfa": _rule_requires_mfa(rule),
        "self_service_registration": _rule_self_service_registration(rule),
        "session": _rule_session(rule),
        "network": _rule_network(rule),
    }


def _policy_rule_settings(raw: RawObject, prefix: str, label: str) -> list[NormalizedObject]:
    """One setting per policy, carrying its active rules and a roll-up.

    The roll-up is the point. An Okta policy is a container and the controls
    live on its rules, so the security question is never "what does this policy
    say" -- it is "does *any* active rule let a session run forever, or skip a
    second factor". An attacker gets the weakest rule, so that is what the
    summary reports, and a policy author does not have to walk the list.

    Only ACTIVE rules count. An inactive rule enforces nothing and including it
    would make a tightened policy look permissive.
    """
    payload = raw.payload
    rules = [r for r in (payload.get("rules") or []) if isinstance(r, dict)]
    active = [r for r in rules if str(r.get("status") or "").upper() == "ACTIVE"]
    summaries = [_summarize_rule(rule) for rule in active]

    mfa_answers = [s["requires_mfa"] for s in summaries if s["requires_mfa"] is not None]
    lifetimes = [
        s["session"].get("max_session_lifetime_minutes")
        for s in summaries
        if isinstance(s["session"].get("max_session_lifetime_minutes"), int)
        and s["session"].get("max_session_lifetime_minutes")
    ]

    return [
        setting_object(
            key=f"okta_policy:{raw.provider_id}",
            category="security",
            label=f"{label}: {payload.get('name') or raw.provider_id}",
            value={
                "name": payload.get("name"),
                "type": payload.get("type"),
                "status": payload.get("status"),
                "is_default": payload.get("system"),
                "rule_count": len(rules),
                "active_rule_count": len(active),
                "any_rule_without_mfa": any(answer is False for answer in mfa_answers),
                "self_service_registration_enabled": any(s["self_service_registration"] is True for s in summaries),
                "any_rule_unlimited_session": any(s["session"].get("unlimited_lifetime") for s in summaries),
                "longest_session_minutes": max(lifetimes) if lifetimes else None,
                "rules": summaries,
            },
            value_type="object",
            description=(f"{label} with its active rules. Okta policies are containers; the controls are on the rules."),
            raw_source=payload,
            provider_id_prefix=prefix,
        )
    ]


# -- perimeter and automation surface ------------------------------

# CIDRs that admit the entire internet. A policy zone containing one of these
# looks like a network control and is not one.
_EVERYTHING_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _zone_entries(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(entry.get("value")) for entry in raw if isinstance(entry, dict) and entry.get("value")]


def _matches_everything(gateways: list[str]) -> bool:
    return any(entry in _EVERYTHING_CIDRS for entry in gateways)


def _hook_setting(raw: RawObject, kind: str, label: str) -> NormalizedObject:
    """One hook, with its callout host but never its URL or auth headers."""
    payload = raw.payload
    channel = payload.get("channel") or {}
    config = channel.get("config") if isinstance(channel, dict) else None
    config = config if isinstance(config, dict) else {}
    events = payload.get("events") or {}
    event_types = events.get("items") if isinstance(events, dict) else None
    return setting_object(
        key=f"okta_{kind}_hook:{raw.provider_id}",
        category="security",
        label=f"{label}: {payload.get('name') or raw.provider_id}",
        value={
            "name": payload.get("name"),
            "status": payload.get("status"),
            "type": payload.get("type"),
            "host": config.get("uri_host"),
            "scheme": config.get("uri_scheme"),
            "insecure_scheme": config.get("uri_scheme") == "http",
            "events": list(event_types or []),
        },
        value_type="object",
        description=(
            "An inline hook runs during authentication and can change its "
            "outcome; an event hook receives identity events. Either way the "
            "endpoint is part of the org's trust boundary."
        ),
        raw_source=payload,
        provider_id_prefix=f"{kind}-hook",
    )
