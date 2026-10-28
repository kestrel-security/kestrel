# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Maps Slack RawObjects into Kestrel NormalizedObjects.

Distinctive vs GitHub / Google Workspace: this connector populates
`oauth_application` / `oauth_scope` / `oauth_grant` — tables that existed in
the schema but were never written by a connector before Slack.

Enterprise Grid depth: org roles, workspaces, Slack Connect
external teams, shared channels, anomaly allowlist settings, and curated
Audit Logs events.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.base import NormalizedObject, NormalizedRelationship, RawObject
from kestrel.connectors.sdk.payload import classify_worker_type
from kestrel.connectors.settings_emit import setting_object, settings_from_mapping

# Conservative sensitivity ruleset for Slack OAuth scopes. Backs
# "excessive OAuth scopes" policies; expand as packs need more signals.
# Live Admin Apps may also set is_sensitive on each scope — that wins.
_SENSITIVE_SCOPES = frozenset(
    {
        "admin",
        "chat:write",
        "chat:write.public",
        "channels:history",
        "channels:read",
        "groups:history",
        "groups:read",
        "im:history",
        "mpim:history",
        "files:read",
        "files:write",
        "users:read.email",
        "users.profile:write",
        "commands",
        "workflow.steps:execute",
        "bookmarks:write",
    }
)

# Only what `team.info` and `admin.teams.settings.info` actually return.
# Neither exposes 2FA enforcement, app approval, or SSO: those were emitted
# from fixture-only fields, so on a live tenant they became setting rows with
# null values -- which made `slack-sso-not-enforced` fire on every workspace.
# Session duration is real but per user; see `_normalize_user_session_setting`.
_SESSION_SETTING_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "session_duration_hours",
        "security",
        "Session duration (hours)",
        "number",
        "How long a sign-in lasts before Slack forces re-authentication, from the session settings applied to this account.",
    ),
]

_TEAM_SETTING_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "domain",
        "workspace",
        "Workspace domain",
        "string",
        "Slack workspace subdomain (team domain).",
    ),
]

_ANOMALY_SETTING_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "anomaly_allowlist_configured",
        "security",
        "Anomaly allowlist configured",
        "boolean",
        "Whether Enterprise anomaly IP/ASN allowlists are configured.",
    ),
]

_PENDING_REQUESTS_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "pending_app_requests",
        "security",
        "Pending app install requests",
        "number",
        "Count of unresolved Slack app install requests on the org/workspace.",
    ),
]

_CONNECT_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "slack_connect_org_connected",
        "sharing",
        "Slack Connect organization connected",
        "boolean",
        "Whether an external organization is connected via Slack Connect.",
    ),
]

_SHARED_CHANNEL_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "external_shared_channel",
        "sharing",
        "Externally shared Slack channel",
        "boolean",
        "Whether a channel is externally shared via Slack Connect.",
    ),
]

# Release C: new setting specs for SSO policy, barriers, retention, invites.
_SSO_POLICY_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "sso_bypass_count",
        "security",
        "SSO policy bypass entity count",
        "number",
        "Number of users or groups that can bypass mandatory SSO (zero means SSO is enforced for all).",
    ),
    (
        "sso_policy_type",
        "security",
        "SSO policy type",
        "string",
        "The SSO policy type returned by admin.auth.policy.getEntities (e.g. email_password).",
    ),
]

_INFORMATION_BARRIER_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "information_barrier_configured",
        "security",
        "Information barrier configured",
        "boolean",
        "Whether at least one information barrier is active in the Enterprise Grid org.",
    ),
]

_CHANNEL_RETENTION_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "retention_days",
        "data_governance",
        "Channel message retention (days)",
        "number",
        "Custom retention period in days for this channel; absent means workspace default applies.",
    ),
    (
        "retention_type",
        "data_governance",
        "Channel retention type",
        "string",
        "The retention policy type: custom, retain_and_delete, or workspace_default.",
    ),
]

_INVITE_REQUEST_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "pending_invite_requests",
        "security",
        "Pending invite requests",
        "number",
        "Count of invite requests that have not been approved or denied.",
    ),
]

# Curated Audit Logs action → Kestrel activity action. Unmapped types dropped
# (login noise intentionally omitted — same pattern as Okta System Log).
# pref_* events are Slack workspace setting changes surfaced in Audit Logs only;
# they map to config.change / sso.change / policy.change but never emit
# current-state settings (those come from admin.teams.settings.info).
_ACTION_CATEGORIES: dict[str, str] = {
    "privilege.grant": "privilege",
    "privilege.revoke": "privilege",
    "identity.add": "identity",
    "identity.deactivate": "identity",
    "identity.guest": "identity",
    "dormant.reactivate": "identity",
    "oauth.scope.expand": "oauth",
    "oauth.app.install": "oauth",
    "oauth.app.revoke": "oauth",
    "sharing.external": "sharing",
    "config.change": "config",
    "sso.change": "sso",
    "policy.change": "policy",
    "threat.detected": "threat",
    "session.reset": "session",
    "mfa.enable": "mfa",
    "mfa.disable": "mfa",
    "data.export": "data",
}

_SLACK_AUDIT_TO_KESTREL: dict[str, str] = {
    # --- Privilege / roles ---
    "role_change_to_admin": "privilege.grant",
    "role_change_to_owner": "privilege.grant",
    "role_assigned": "privilege.grant",
    "role_change_to_user": "privilege.revoke",
    "role_removed": "privilege.revoke",
    # --- Identity ---
    "user_deactivated": "identity.deactivate",
    "guest_deactivated": "identity.deactivate",
    "guest_created": "identity.guest",
    "user_created": "identity.add",
    "user_reactivated": "dormant.reactivate",
    # --- OAuth apps ---
    "app_installed": "oauth.app.install",
    "app_scopes_expanded": "oauth.scope.expand",
    "app_uninstalled": "oauth.app.revoke",
    "app_approved": "oauth.app.install",
    "app_restricted": "oauth.app.revoke",
    # --- External sharing ---
    "external_shared_channel_connected": "sharing.external",
    "external_shared_channel_invite_accepted": "sharing.external",
    "external_shared_channel_invite_sent": "sharing.external",
    "file_public_link_created": "sharing.external",
    "file_shared_externally": "sharing.external",
    "slack_connect_invite_sent": "sharing.external",
    "slack_connect_invite_accepted": "sharing.external",
    # --- Session / auth ---
    "user_session_reset_by_admin": "session.reset",
    "user_sessions_reset_by_anomaly_event_response": "threat.detected",
    "user_session_invalidated": "session.reset",
    # --- SSO / auth policy pref_* events ---
    "pref.sso_setting_changed": "sso.change",
    "pref.two_factor_authentication_requirement_changed": "policy.change",
    "pref.allow_calls": "config.change",
    "pref.allow_message_deletion": "config.change",
    "pref.app_whitelisting_enabled": "policy.change",
    "pref.can_receive_shared_channels_invites_from_external_teams_enable": "config.change",
    "pref.compliance_export_start": "data.export",
    "pref.custom_tos_acknowledged": "config.change",
    "pref.data_residency_location_change": "policy.change",
    "pref.dnd_activated": "config.change",
    "pref.dnd_end_hour": "config.change",
    "pref.dnd_start_hour": "config.change",
    "pref.email_confirmed": "config.change",
    "pref.email_display_change": "config.change",
    "pref.emoji_added_to_workspace": "config.change",
    "pref.gateway_url": "config.change",
    "pref.hide_hex_codes": "config.change",
    "pref.invite_accept_admin_approval": "policy.change",
    "pref.invites_limit": "policy.change",
    "pref.invites_only_admins": "policy.change",
    "pref.loud_channel_mentions_limit": "config.change",
    "pref.msg_edit_window_mins": "config.change",
    "pref.no_retention_days": "policy.change",
    "pref.notification_redaction_type": "config.change",
    "pref.outgoing_email_route": "config.change",
    "pref.public_channel_conversion_privilege": "policy.change",
    "pref.receive_external_emails": "config.change",
    "pref.require_at_for_mention": "config.change",
    "pref.retention_duration": "policy.change",
    "pref.retention_type": "policy.change",
    "pref.show_join_leave": "config.change",
    "pref.subteam_self_add": "policy.change",
    "pref.who_can_at_channel": "policy.change",
    "pref.who_can_at_everyone": "policy.change",
    "pref.who_can_change_team_profile": "policy.change",
    "pref.who_can_create_channels": "policy.change",
    "pref.who_can_create_delete_user_groups": "policy.change",
    "pref.who_can_create_shared_channels": "policy.change",
    "pref.who_can_create_workflows": "policy.change",
    "pref.who_can_dm_anyone": "policy.change",
    "pref.who_can_manage_channel_posting_prefs": "policy.change",
    "pref.who_can_manage_ext_shared_channels": "policy.change",
    "pref.who_can_manage_integrations": "policy.change",
    "pref.who_can_post_in_channel": "policy.change",
    "pref.who_can_view_calls_history": "config.change",
    "pref.who_can_view_message_activity": "config.change",
    # --- Channel management ---
    "channel_created": "config.change",
    "channel_deleted": "config.change",
    "channel_archived": "config.change",
    "channel_unarchived": "config.change",
    "channel_converted_to_private": "config.change",
    "channel_converted_to_public": "config.change",
    "channel_name_changed": "config.change",
    "channel_posting_permissions_updated": "policy.change",
    "channel_retention_changed": "policy.change",
    # --- Workflow ---
    "workflow_created": "config.change",
    "workflow_deleted": "config.change",
    "workflow_enabled": "config.change",
    "workflow_disabled": "config.change",
    "workflow_shared_externally": "sharing.external",
    "workflow_published": "config.change",
    # --- Information barriers ---
    "barrier_created": "policy.change",
    "barrier_deleted": "policy.change",
    "barrier_updated": "policy.change",
    # --- EKM / encryption ---
    "ekm_enrolled": "policy.change",
    "ekm_unenrolled": "policy.change",
    "ekm_key_logs_slack_opaque": "policy.change",
    # --- IdP groups ---
    "idp_configuration_added": "policy.change",
    "idp_configuration_removed": "policy.change",
    "idp_group_linked": "policy.change",
    "idp_group_unlinked": "policy.change",
    # --- MFA ---
    "user_set_mfa_enabled": "mfa.enable",
    "user_set_mfa_disabled": "mfa.disable",
    # --- Data export ---
    "data_export": "data.export",
    "export_started": "data.export",
    "export_completed": "data.export",
    # --- Anomaly detection ---
    "anomaly_detection_enabled": "config.change",
    "anomaly_detection_disabled": "config.change",
    "anomaly_detection_ip_added": "config.change",
    "anomaly_detection_ip_removed": "config.change",
}


def _is_sensitive_scope(scope_name: str) -> bool:
    return scope_name in _SENSITIVE_SCOPES or scope_name.startswith("admin.")


def _profile(user: dict[str, Any]) -> dict[str, Any]:
    profile = user.get("profile")
    return profile if isinstance(profile, dict) else {}


def _installer_user_id(payload: dict[str, Any]) -> str | None:
    if payload.get("installer_user_id"):
        return str(payload["installer_user_id"])
    last_resolved = payload.get("last_resolved_by")
    if isinstance(last_resolved, dict) and last_resolved.get("actor_id"):
        return str(last_resolved["actor_id"])
    return None


def _parse_slack_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 10_000_000_000:
            ts = ts / 1000
        return datetime.fromtimestamp(ts, tz=UTC)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            return _parse_slack_ts(int(text))
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _anomaly_allowlist_configured(payload: dict[str, Any]) -> bool:
    trusted_cidrs = payload.get("trusted_cidrs") or payload.get("trustedCidrs") or []
    trusted_asns = payload.get("trusted_asns") or payload.get("trustedAsns") or []
    if isinstance(trusted_cidrs, list) and trusted_cidrs:
        return True
    if isinstance(trusted_asns, list) and trusted_asns:
        return True
    # Explicit false when keys present but empty (fixture-proven).
    if "trusted_cidrs" in payload or "trusted_asns" in payload:
        return False
    if "trustedCidrs" in payload or "trustedAsns" in payload:
        return False
    return False


class SlackNormalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        method = getattr(self, f"_normalize_{object_type}", None)
        if method is None:
            raise ValueError(f"SlackNormalizer does not support object_type '{object_type}'")
        return method(raw)

    def _normalize_team(self, raw: RawObject) -> list[NormalizedObject]:
        return settings_from_mapping(raw.payload, _TEAM_SETTING_SPECS, provider_id_prefix="org-setting")

    def _normalize_user(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        profile = _profile(payload)
        is_bot = bool(payload.get("is_bot") or payload.get("id") == "USLACKBOT")
        # A real sign-in comes from Audit Logs (`last_login_at`, stitched on by
        # the collector). `updated` is the profile's modification time -- kept
        # only as a labeled fallback so the UI can still show *something*, and
        # dormancy policies know not to trust it.
        last_login = _parse_slack_ts(payload.get("last_login_at"))
        last_active = last_login or _parse_slack_ts(payload.get("last_active_at") or payload.get("updated"))
        if last_login is not None:
            last_active_source: str | None = "audit"
        elif payload.get("last_active_at"):
            last_active_source = "analytics"
        elif last_active is not None:
            last_active_source = "profile"
        else:
            last_active_source = None
        guest_type = (
            "single_channel_guest"
            if payload.get("is_ultra_restricted")
            else ("multi_channel_guest" if payload.get("is_restricted") else None)
        )
        attrs: dict[str, Any] = {
            "identity_type": "service_account" if is_bot else "user",
            "display_name": (profile.get("real_name") or payload.get("real_name") or payload.get("name") or raw.provider_id),
            "email": profile.get("email") or payload.get("email"),
            "is_disabled": bool(payload.get("deleted")),
            "is_external": bool(payload.get("is_restricted") or payload.get("is_ultra_restricted")),
            "mfa_enabled": payload.get("has_2fa"),
            # Slack guest tiers: a single-channel guest can only ever see one
            # channel; a multi-channel guest is invited channel by channel.
            "guest_type": guest_type,
            "is_admin": bool(payload.get("is_admin")),
            "is_owner": bool(payload.get("is_owner") or payload.get("is_primary_owner")),
            # A full member is not provably an employee: Slack has no user
            # type, so only guests and bots classify here.
            "worker_type": classify_worker_type(None, is_guest=guest_type is not None, is_bot=is_bot),
            "title": profile.get("title") or None,
        }
        if last_active is not None:
            attrs["last_active_at"] = last_active
            attrs["last_active_source"] = last_active_source
        # Guest expiration: Slack returns expiration_ts on guest records when
        # the admin set an expiry.  Map to expires_at so policies can check
        # whether guests have an expiry set.
        expires_at = _parse_slack_ts(payload.get("expiration_ts"))
        if expires_at is not None:
            attrs["expires_at"] = expires_at
        return [
            NormalizedObject(
                kind="identity",
                provider_id=raw.provider_id,
                attributes=attrs,
                raw_source=payload,
            )
        ]

    def _normalize_usergroup(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="group",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload.get("handle") or payload.get("name") or raw.provider_id,
                    "description": payload.get("description"),
                },
                raw_source=payload,
            )
        ]

    def _normalize_usergroup_member(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        group_id = str(payload["usergroup_id"])
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
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "direct",
                    "identity_ref": identity_id,
                    "role_ref": role_id,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role",
                        source_ref=identity_id,
                        target_ref=role_id,
                        access_path="direct",
                    )
                ],
            )
        ]

    def _normalize_oauth_app(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        developer = payload.get("developer_type")
        publisher = payload.get("publisher")
        if publisher is None and isinstance(developer, dict):
            publisher = developer.get("type")
        nested = payload.get("app")
        name = payload.get("name")
        if not name and isinstance(nested, dict):
            name = nested.get("name")
        return [
            NormalizedObject(
                kind="oauth_application",
                provider_id=raw.provider_id,
                attributes={
                    "name": name or raw.provider_id,
                    "publisher": publisher,
                    "is_verified": payload.get("is_app_directory_approved"),
                    "owner_identity_ref": _installer_user_id(payload),
                },
                raw_source=payload,
            )
        ]

    def _normalize_oauth_scope(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        scope_name = str(payload["scope_name"])
        sensitive = bool(payload["is_sensitive"]) if "is_sensitive" in payload else _is_sensitive_scope(scope_name)
        return [
            NormalizedObject(
                kind="oauth_scope",
                provider_id=raw.provider_id,
                attributes={
                    "oauth_application_ref": str(payload["app_id"]),
                    "scope_name": scope_name,
                    "is_sensitive": sensitive,
                },
                raw_source=payload,
            )
        ]

    def _normalize_oauth_grant(self, raw: RawObject) -> list[NormalizedObject]:
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
                    "granted_at": payload.get("date_installed") or payload.get("granted_at"),
                    "last_used_at": payload.get("last_active") or payload.get("last_used_at"),
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

    def _normalize_workspace(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        objects: list[NormalizedObject] = [
            NormalizedObject(
                kind="group",
                provider_id=f"workspace:{raw.provider_id}",
                attributes={
                    "name": payload.get("name") or payload.get("domain") or raw.provider_id,
                    "description": f"Slack workspace {raw.provider_id}",
                },
                raw_source=payload,
            )
        ]
        # Only keys the payload actually carries. The previous guard emitted every
        # spec whenever *any* value was present, and `domain` always is -- so a
        # live workspace got a full set of settings whose values were null.
        settings_payload = {key: payload[key] for key, *_ in _TEAM_SETTING_SPECS if payload.get(key) is not None}
        if settings_payload:
            objects.extend(
                settings_from_mapping(
                    settings_payload,
                    _TEAM_SETTING_SPECS,
                    provider_id_prefix=f"workspace-setting-{raw.provider_id}",
                )
            )
        return objects

    def _normalize_org_role(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="role",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload.get("name") or raw.provider_id,
                    "is_privileged": bool(payload.get("is_privileged", True)),
                },
                raw_source=payload,
            )
        ]

    def _normalize_org_role_assignment(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        role_id = str(payload["role_id"])
        identity_id = str(payload["user_id"])
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "direct",
                    "identity_ref": identity_id,
                    "role_ref": role_id,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role",
                        source_ref=identity_id,
                        target_ref=role_id,
                        access_path="direct",
                    )
                ],
            )
        ]

    def _normalize_restricted_app(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="oauth_application",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload.get("name") or raw.provider_id,
                    "publisher": payload.get("publisher"),
                    "is_verified": False,
                    "owner_identity_ref": _installer_user_id(payload),
                },
                raw_source=payload,
            )
        ]

    def _normalize_app_request(self, raw: RawObject) -> list[NormalizedObject]:
        # Aggregated count is emitted once per request row via a stable setting
        # key in the collector→evaluate path; each pending request becomes a
        # tenant_setting row so policies can match pending_app_requests > 0.
        return settings_from_mapping(
            {"pending_app_requests": 1},
            _PENDING_REQUESTS_SPECS,
            provider_id_prefix=f"app-request-{raw.provider_id}",
        )

    def _normalize_external_team(self, raw: RawObject) -> list[NormalizedObject]:
        return settings_from_mapping(
            {"slack_connect_org_connected": True},
            _CONNECT_SPECS,
            provider_id_prefix=f"connect-{raw.provider_id}",
        )

    def _normalize_channel(self, raw: RawObject) -> list[NormalizedObject]:
        """Channel inventory row plus, where membership was read, one grant per
        member so a guest in a private channel is a real access row."""
        payload = raw.payload
        objects = self._channel_resource(raw)
        member_ids = payload.get("member_ids")
        if isinstance(member_ids, list):
            for member_id in member_ids:
                member = str(member_id)
                objects.append(
                    NormalizedObject(
                        kind="grant",
                        provider_id=f"{raw.provider_id}:{member}",
                        attributes={
                            "identity_ref": member,
                            "resource_ref": raw.provider_id,
                            "granted_via": "direct",
                            "permission_level": "member",
                        },
                        raw_source={"channel_id": raw.provider_id, "user_id": member},
                        relationships=[
                            NormalizedRelationship(
                                edge_type="can_access",
                                source_ref=member,
                                target_ref=raw.provider_id,
                                access_path="direct",
                                properties={"permission_level": "member"},
                            )
                        ],
                    )
                )
        return objects

    def _channel_resource(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        name = payload.get("name") or payload.get("name_normalized") or raw.provider_id
        is_ext = bool(payload.get("is_ext_shared") or payload.get("is_shared") or payload.get("is_global_shared"))
        visibility = "private" if payload.get("is_private") else "public"
        member_count = payload.get("member_count") or payload.get("num_members")
        return [
            NormalizedObject(
                kind="resource",
                provider_id=raw.provider_id,
                attributes={
                    "name": name,
                    "resource_type": "channel",
                    "visibility": visibility,
                    "is_external": is_ext,
                    "member_count": member_count,
                    # `config` is the JSONB column the Resource row keeps, so
                    # policies can read these; the flat attributes above feed
                    # the graph node.
                    "config": {
                        "is_external": is_ext,
                        "is_private": visibility == "private",
                        "is_archived": bool(payload.get("is_archived")),
                        "member_count": member_count,
                        "connected_team_ids": list(payload.get("connected_team_ids") or []),
                    },
                },
                raw_source=payload,
            )
        ]

    def _normalize_shared_channel(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        is_ext = bool(payload.get("is_ext_shared") or payload.get("is_shared") or payload.get("is_global_shared"))
        objects = self._channel_resource(raw)
        if is_ext:
            objects.extend(
                settings_from_mapping(
                    {"external_shared_channel": True},
                    _SHARED_CHANNEL_SPECS,
                    provider_id_prefix=f"shared-channel-{raw.provider_id}",
                )
            )
        return objects

    def _normalize_user_session_setting(self, raw: RawObject) -> list[NormalizedObject]:
        """Session duration for one account, scoped to the identity it governs.

        Slack reports `duration` in seconds. A row only exists for users with
        settings explicitly applied; the rest are absent from the response and
        get no row, because "Slack's default" and "not collected" are different
        claims and the connector does not know which it is looking at.
        """
        payload = raw.payload
        duration = payload.get("duration")
        if not isinstance(duration, int | float) or duration <= 0:
            return []
        obj = setting_object(
            key="session_duration_hours",
            category="security",
            label="Session duration (hours)",
            value=round(duration / 3600, 2),
            value_type="number",
            description=_SESSION_SETTING_SPECS[0][4],
            raw_source=payload,
            provider_id_prefix=f"user-setting:{raw.provider_id}",
        )
        obj.attributes["subject_type"] = "identity"
        obj.attributes["subject_ref"] = raw.provider_id
        obj.relationships = [
            NormalizedRelationship(
                edge_type="applies_to",
                source_ref=obj.provider_id,
                target_ref=raw.provider_id,
            )
        ]
        return [obj]

    def _normalize_anomaly_allowlist(self, raw: RawObject) -> list[NormalizedObject]:
        configured = _anomaly_allowlist_configured(raw.payload)
        return settings_from_mapping(
            {"anomaly_allowlist_configured": configured},
            _ANOMALY_SETTING_SPECS,
            provider_id_prefix="org-setting",
        )

    def _normalize_audit_log(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        action = _kestrel_action_for_slack_audit(payload)
        if action is None:
            return []
        actor = payload.get("actor") if isinstance(payload.get("actor"), dict) else {}
        entity = payload.get("entity") if isinstance(payload.get("entity"), dict) else {}
        actor_user: dict[str, Any] = {}
        raw_actor_user = actor.get("user") if isinstance(actor, dict) else None
        if isinstance(raw_actor_user, dict):
            actor_user = raw_actor_user
        entity_user: dict[str, Any] = {}
        raw_entity_user = entity.get("user") if isinstance(entity, dict) else None
        if isinstance(raw_entity_user, dict):
            entity_user = raw_entity_user
        occurred = _parse_slack_ts(payload.get("date_create"))
        summary_action = str(payload.get("action") or action)
        actor_id = actor_user.get("id")
        entity_id = entity_user.get("id")
        return [
            NormalizedObject(
                kind="event",
                provider_id=raw.provider_id,
                attributes={
                    "action": action,
                    "action_category": _ACTION_CATEGORIES.get(action, "other"),
                    "actor_email": actor_user.get("email") or actor_user.get("name"),
                    "actor_provider_id": str(actor_id) if actor_id else None,
                    "target_email": entity_user.get("email") or entity_user.get("name"),
                    "target_type": "identity" if entity_user else None,
                    "target_provider_id": str(entity_id) if entity_id else None,
                    "occurred_at": occurred,
                    "summary": f"Slack Audit Logs: {summary_action} ({action})",
                    "attributes": {
                        "slack_action": summary_action,
                    },
                },
                raw_source=payload,
            )
        ]

    # ------------------------------------------------------------------ #
    # Release C — new object types                                         #
    # ------------------------------------------------------------------ #

    def _normalize_sso_policy(self, raw: RawObject) -> list[NormalizedObject]:
        """SSO policy assignments from admin.auth.policy.getEntities.

        ``sso_bypass_count > 0`` means users/groups can authenticate without
        SSO, which is the signal ``slack-sso-not-enforced`` checks.
        """
        payload = raw.payload
        entities = payload.get("entities") or []
        bypass_count = len(entities) if isinstance(entities, list) else 0
        policy_type = payload.get("policy_type") or payload.get("type") or "unknown"
        setting_payload = {
            "sso_bypass_count": bypass_count,
            "sso_policy_type": str(policy_type),
        }
        return settings_from_mapping(
            setting_payload,
            _SSO_POLICY_SPECS,
            provider_id_prefix="org-sso-policy",
        )

    def _normalize_information_barrier(self, raw: RawObject) -> list[NormalizedObject]:
        """One information barrier → a tenant_setting row for barrier existence.

        Policies check ``information_barrier_configured`` being ``False`` (no
        rows returned by the collector) as the finding, not individual barriers.
        """
        return settings_from_mapping(
            {"information_barrier_configured": True},
            _INFORMATION_BARRIER_SPECS,
            provider_id_prefix=f"barrier-{raw.provider_id}",
        )

    def _normalize_workflow(self, raw: RawObject) -> list[NormalizedObject]:
        """Workflow resource for governance checks."""
        payload = raw.payload
        app_raw = payload.get("app")
        app_info = app_raw if isinstance(app_raw, dict) else {}
        trigger_type = payload.get("trigger_type") or payload.get("trigger_id") or "unknown"
        is_external = bool(
            payload.get("is_external_steps_enabled")
            or payload.get("shared_externally")
            or payload.get("is_published_to_directory")
        )
        return [
            NormalizedObject(
                kind="resource",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload.get("title") or payload.get("name") or raw.provider_id,
                    "resource_type": "workflow",
                    "is_external": is_external,
                    "config": {
                        "trigger_type": trigger_type,
                        "is_external": is_external,
                        "app_id": app_info.get("id") or payload.get("app_id"),
                        "app_name": app_info.get("name") or payload.get("app_name"),
                        "is_published": bool(payload.get("is_published") or payload.get("is_published_to_directory")),
                        "collaborator_count": payload.get("collaborator_count"),
                        "run_count": payload.get("run_count"),
                    },
                },
                raw_source=payload,
            )
        ]

    def _normalize_channel_retention(self, raw: RawObject) -> list[NormalizedObject]:
        """Custom retention policy for one channel.

        ``channel_id`` comes from the provider_id; retention_days and
        retention_type come from the admin.conversations.getCustomRetention
        response.  A channel without any custom policy produces no row (the
        collector skips empty responses).
        """
        payload = raw.payload
        duration_days = payload.get("duration") or payload.get("retention_duration")
        retention_type = payload.get("type") or payload.get("retention_type") or "custom"
        channel_id = raw.provider_id.split("retention:")[1] if raw.provider_id.startswith("retention:") else raw.provider_id
        setting_payload: dict[str, Any] = {"retention_type": str(retention_type)}
        if isinstance(duration_days, (int, float)) and duration_days > 0:
            setting_payload["retention_days"] = int(duration_days)
        objects = settings_from_mapping(
            setting_payload,
            _CHANNEL_RETENTION_SPECS,
            provider_id_prefix=f"channel-retention-{channel_id}",
        )
        for obj in objects:
            obj.attributes["subject_type"] = "resource"
            obj.attributes["subject_ref"] = channel_id
            obj.relationships = [
                NormalizedRelationship(
                    edge_type="applies_to",
                    source_ref=obj.provider_id,
                    target_ref=channel_id,
                )
            ]
        return objects

    def _normalize_invite_request(self, raw: RawObject) -> list[NormalizedObject]:
        """Pending invite request → a count-contribution setting row.

        Similar to app_request: one row per pending request; the value is the
        count contribution.  Policies check ``pending_invite_requests > 0`` and
        ``days_pending`` for staleness.
        """
        payload = raw.payload
        days_pending = payload.get("days_pending")
        setting_payload: dict[str, Any] = {"pending_invite_requests": 1}
        if isinstance(days_pending, (int, float)):
            setting_payload["days_pending"] = int(days_pending)
        return settings_from_mapping(
            setting_payload,
            _INVITE_REQUEST_SPECS,
            provider_id_prefix=f"invite-request-{raw.provider_id}",
        )


def _kestrel_action_for_slack_audit(payload: dict[str, Any]) -> str | None:
    action = payload.get("action")
    if not isinstance(action, str):
        return None
    if action in _SLACK_AUDIT_TO_KESTREL:
        return _SLACK_AUDIT_TO_KESTREL[action]
    # pref_* events not in the explicit table fall back to config.change so
    # they are still surfaced rather than silently dropped.  The explicit table
    # covers the security-relevant subset; everything else is workspace noise.
    if action.startswith("pref."):
        return "config.change"
    return None
