# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Translates GoogleWorkspaceClient responses into RawObjects, one per
manifest object_type.

As with the GitHub connector, cross-cutting joins happen here so the
normalizer stays a pure single-object mapping function. Two Workspace
specifics drive that: group members and drive permissions are only
reachable per-parent (so the parent id is stitched onto each child payload),
and the Drive API identifies grantees by email while the Directory API
identifies them by numeric id -- the collector resolves that mismatch once,
rather than making the normalizer re-derive it for every permission.

v0.2 adds: Cloud Identity Policy API settings, mobile/ChromeOS devices,
Alert Center alerts, inbound SAML SSO, admin/drive/saml/groups/mobile
Reports feeds, and synthetic dwd_client objects from admin audit.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.base import HealthCheckResult, RawObject
from kestrel.connectors.sdk.payload import sub_dict

from kestrel_connector_google_workspace.client import GoogleWorkspaceClient
from kestrel_connector_google_workspace.health import check_health, classify_gws_failure
from kestrel_connector_google_workspace.http import is_skippable

logger = logging.getLogger(__name__)

OBJECT_TYPES = [
    "domain",
    "domain_list",
    "org_unit",
    "user",
    "group",
    "group_member",
    "group_setting",
    "admin_role",
    "role_assignment",
    "shared_drive",
    "drive_permission",
    # Per-user OAuth grants (Directory users.tokens): the current consent state.
    "user_token",
    # Admin Reports login events (cursored): failures, suspicious sign-ins, 2SV changes.
    "login_activity",
    # v0.2 additions
    "customer",
    "policy",
    "mobile_device",
    "chromeos_device",
    "alert",
    "inbound_sso_profile",
    "inbound_sso_assignment",
    "admin_activity",
    "drive_activity",
    "saml_activity",
    "user_accounts_activity",
    "groups_activity",
    "mobile_activity",
    "dwd_client",
]

# Object types with incremental (cursored) collection. The `collect` dispatcher
# passes `since` to the method for these.
_INCREMENTAL_OBJECT_TYPES = frozenset({"login_activity", "admin_activity", "drive_activity"})

# Per-user token reads fan out one call per active user; a small pool keeps a
# large directory inside the time budget without tripping Google's per-user
# quota. The transport handles 429 / Retry-After for each worker.
TOKEN_FAN_OUT_WORKERS = 4


# Families a delegated admin without the matching Admin SDK privilege cannot
# read. Each is recorded under its own name so the run reports exactly what is
# missing; the directory (users, groups) is the spine and still fails hard.
OPTIONAL_OBJECT_TYPES = frozenset(
    {
        "domain",
        "domain_list",
        "org_unit",
        "group_setting",
        "admin_role",
        "role_assignment",
        "shared_drive",
        "drive_permission",
        "user_token",
        "login_activity",
        # v0.2
        "customer",
        "policy",
        "mobile_device",
        "chromeos_device",
        "alert",
        "inbound_sso_profile",
        "inbound_sso_assignment",
        "admin_activity",
        "drive_activity",
        "saml_activity",
        "user_accounts_activity",
        "groups_activity",
        "mobile_activity",
        "dwd_client",
    }
)


class GoogleWorkspaceCollector:
    def __init__(self, client: GoogleWorkspaceClient) -> None:
        self.client = client
        # object_type / sub-family -> failure class, read by the sync pipeline.
        self.skipped_object_types: dict[str, str] = {}
        self._org_units: dict[str, dict[str, Any]] | None = None
        self._customer_domains_cache: set[str] | None = None

    def discover(self) -> list[str]:
        return list(OBJECT_TYPES)

    def health_check(self) -> HealthCheckResult:
        return check_health(self.client)

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        method = getattr(self, f"_collect_{object_type}", None)
        if method is None:
            raise ValueError(f"GoogleWorkspaceCollector does not support object_type '{object_type}'")
        try:
            now = datetime.now(UTC)
            if object_type in _INCREMENTAL_OBJECT_TYPES:
                yield from method(now, since=since)
                return
            yield from method(now)
        except Exception as exc:
            if object_type in OPTIONAL_OBJECT_TYPES and is_skippable(exc):
                failure = classify_gws_failure(exc)
                self.skipped_object_types[object_type] = failure
                logger.warning(
                    "Google Workspace %s skipped (%s); the rest of the tenant still collects", object_type, failure
                )
                return
            raise

    def _safe_list(self, family: str, fn: Callable[..., list[dict[str, Any]]], *args: Any) -> list[dict[str, Any]]:
        """A per-parent listing (members of one group, permissions of one
        drive) that may be gated on some parents but not others."""
        try:
            return list(fn(*args))
        except Exception as exc:
            if not is_skippable(exc):
                raise
            self.skipped_object_types.setdefault(family, classify_gws_failure(exc))
            return []

    def _collect_domain(self, now: datetime) -> Iterable[RawObject]:
        domain = self.client.get_domain()
        yield RawObject(object_type="domain", provider_id=domain["domainName"], payload=domain, collected_at=now)

    def _collect_domain_list(self, now: datetime) -> Iterable[RawObject]:
        for domain in self.client.list_domains():
            name = str(domain.get("domainName") or "")
            if not name:
                continue
            yield RawObject(object_type="domain_list", provider_id=name, payload=domain, collected_at=now)

    def _org_units_by_path(self) -> dict[str, dict[str, Any]]:
        if self._org_units is None:
            units = self._safe_list("org_unit", self.client.list_org_units)
            self._org_units = {str(u.get("orgUnitPath") or ""): u for u in units if u.get("orgUnitId")}
        return self._org_units

    def _collect_org_unit(self, now: datetime) -> Iterable[RawObject]:
        for unit in self.client.list_org_units():
            unit_id = str(unit.get("orgUnitId") or "")
            if not unit_id:
                continue
            yield RawObject(object_type="org_unit", provider_id=unit_id, payload=unit, collected_at=now)

    def _collect_user(self, now: datetime) -> Iterable[RawObject]:
        units = self._org_units_by_path()
        for user in self.client.list_users():
            payload = dict(user)
            unit = units.get(str(user.get("orgUnitPath") or ""))
            if unit is not None:
                payload["org_unit_id"] = str(unit["orgUnitId"])
            yield RawObject(object_type="user", provider_id=str(user["id"]), payload=payload, collected_at=now)

    def _collect_group(self, now: datetime) -> Iterable[RawObject]:
        for group in self.client.list_groups():
            yield RawObject(object_type="group", provider_id=str(group["id"]), payload=group, collected_at=now)

    def _collect_group_setting(self, now: datetime) -> Iterable[RawObject]:
        """Groups Settings API, one call per group. A group the credential
        cannot read is recorded once as a sub-family skip."""
        for group in self.client.list_groups():
            email = str(group.get("email") or "")
            group_id = str(group["id"])
            if not email:
                continue
            try:
                settings = self.client.get_group_settings(email)
            except Exception as exc:
                if not is_skippable(exc):
                    raise
                self.skipped_object_types.setdefault("group_setting", classify_gws_failure(exc))
                return
            payload = dict(settings)
            payload["group_id"] = group_id
            payload["group_email"] = email
            yield RawObject(object_type="group_setting", provider_id=group_id, payload=payload, collected_at=now)

    def _customer_domains(self) -> set[str]:
        """Domains that count as inside the tenant, degrading honestly.

        A gated domains list narrows "inside" to the primary domain alone and
        is recorded under ``group_member.domains``, so the run is PARTIAL and
        the operator can read the external-member results as approximate.
        Anything else (a throttle, a 5xx) raises: guessing would mark every
        alias-domain member external on a run that reported full coverage.
        """
        if self._customer_domains_cache is not None:
            return self._customer_domains_cache
        try:
            names = set(self.client.customer_domains())
        except Exception as exc:
            if not is_skippable(exc):
                raise
            self.skipped_object_types.setdefault("group_member.domains", classify_gws_failure(exc))
            names = {self.client.domain.strip().lower()}
        self._customer_domains_cache = names
        return names

    def _collect_group_member(self, now: datetime) -> Iterable[RawObject]:
        customer_domains = self._customer_domains()
        directory_ids = {str(u["id"]) for u in self.client.list_users()}
        groups_by_id = {str(g["id"]): g for g in self.client.list_groups()}
        for group in self.client.list_groups():
            group_id = str(group["id"])
            for member in self._safe_list("group_member.members", self.client.list_group_members, group_id):
                enriched = dict(member)
                enriched["group_id"] = group_id
                member_id = str(member.get("id") or "")
                member_type = str(member.get("type") or "USER").upper()
                email = str(member.get("email") or "").strip().lower()
                email_domain = email.rsplit("@", 1)[-1] if "@" in email else ""
                enriched["is_external"] = bool(email_domain) and email_domain not in customer_domains
                enriched["is_directory_user"] = member_type == "USER" and member_id in directory_ids
                if member_type == "GROUP" and member_id in groups_by_id:
                    # Nested group: carry the child group's own payload so the
                    # normalizer re-emits it identically (no attribute churn).
                    enriched["nested_group"] = groups_by_id[member_id]
                # Composite id: a member row is only unique within its group,
                # and the same user legitimately belongs to several groups.
                provider_id = f"{group_id}:{member['id']}"
                yield RawObject(
                    object_type="group_member",
                    provider_id=provider_id,
                    payload=enriched,
                    collected_at=now,
                )

    # Stand-in roles when the role-management API is gated. Their ids cannot
    # collide with Google's numeric roleIds.
    _FLAG_ROLES: tuple[tuple[str, str, str, bool], ...] = (
        ("isAdmin", "flag:super_admin", "Super Admin", True),
        ("isDelegatedAdmin", "flag:delegated_admin", "Delegated Admin", False),
    )

    def _role_management_gated(self, exc: BaseException) -> bool:
        if not is_skippable(exc):
            return False
        self.skipped_object_types.setdefault("admin_role", classify_gws_failure(exc))
        self.skipped_object_types.setdefault("role_assignment", classify_gws_failure(exc))
        logger.warning(
            "Google Workspace role management is gated (%s); admin standing is derived from directory user flags",
            classify_gws_failure(exc),
        )
        return True

    def _collect_admin_role(self, now: datetime) -> Iterable[RawObject]:
        try:
            roles = list(self.client.list_roles())
        except Exception as exc:
            if not self._role_management_gated(exc):
                raise
            for _flag, role_id, label, is_super in self._FLAG_ROLES:
                yield RawObject(
                    object_type="admin_role",
                    provider_id=role_id,
                    payload={
                        "roleId": role_id,
                        "roleName": role_id,
                        "roleDescription": label,
                        "isSuperAdminRole": is_super,
                        "isSystemRole": True,
                        "synthetic_from_user_flag": True,
                    },
                    collected_at=now,
                )
            return
        for role in roles:
            yield RawObject(
                object_type="admin_role",
                provider_id=str(role["roleId"]),
                payload=role,
                collected_at=now,
            )

    def _collect_role_assignment(self, now: datetime) -> Iterable[RawObject]:
        try:
            assignments = list(self.client.list_role_assignments())
        except Exception as exc:
            if not self._role_management_gated(exc):
                raise
            # The directory still says who is an admin: isAdmin is Super
            # Admin, isDelegatedAdmin is any delegated role. Coarser than the
            # real assignment list, and reported as reduced coverage.
            for user in self.client.list_users():
                for flag, role_id, _label, _is_super in self._FLAG_ROLES:
                    if not user.get(flag):
                        continue
                    user_id = str(user["id"])
                    yield RawObject(
                        object_type="role_assignment",
                        provider_id=f"{role_id}:{user_id}",
                        payload={
                            "roleAssignmentId": f"{role_id}:{user_id}",
                            "roleId": role_id,
                            "assignedTo": user_id,
                            "scopeType": "CUSTOMER",
                            "synthetic_from_user_flag": True,
                        },
                        collected_at=now,
                    )
            return
        for assignment in assignments:
            yield RawObject(
                object_type="role_assignment",
                provider_id=str(assignment["roleAssignmentId"]),
                payload=assignment,
                collected_at=now,
            )

    def _collect_shared_drive(self, now: datetime) -> Iterable[RawObject]:
        for drive in self.client.list_shared_drives():
            yield RawObject(object_type="shared_drive", provider_id=str(drive["id"]), payload=drive, collected_at=now)

    def _collect_drive_permission(self, now: datetime) -> Iterable[RawObject]:
        # Drive permissions name their grantee by email; the directory keys
        # identities and groups by numeric id. Resolve once here so every
        # permission payload carries the ids the normalizer needs to emit
        # references, instead of re-listing the directory per permission.
        users_by_email = {u["primaryEmail"].lower(): str(u["id"]) for u in self.client.list_users()}
        groups_by_email = {g["email"].lower(): str(g["id"]) for g in self.client.list_groups()}

        for drive in self.client.list_shared_drives():
            drive_id = str(drive["id"])
            for permission in self._safe_list("drive_permission.permissions", self.client.list_drive_permissions, drive_id):
                enriched = dict(permission)
                enriched["drive_id"] = drive_id
                email = (permission.get("emailAddress") or "").lower()
                enriched["resolved_user_id"] = users_by_email.get(email)
                enriched["resolved_group_id"] = groups_by_email.get(email)
                yield RawObject(
                    object_type="drive_permission",
                    provider_id=f"{drive_id}:{permission['id']}",
                    payload=enriched,
                    collected_at=now,
                )

    def _collect_user_token(self, now: datetime) -> Iterable[RawObject]:
        """One RawObject per (user, OAuth client) consent.

        The first user probes the privilege: a 403 there is the
        `user.security` scope missing for the whole tenant, recorded once
        rather than once per user. Later per-user failures are individual
        (a suspended user answers 404) and are recorded as a sub-family.
        """
        users = [u for u in self.client.list_users() if not (u.get("suspended") or u.get("archived"))]
        if not users:
            return
        first, rest = users[0], users[1:]
        # Probe with the first user inside the family's own error handling.
        first_tokens = self.client.list_user_tokens(str(first["id"]))
        yield from self._token_objects(first, first_tokens, now)

        def fetch(user: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]] | None, BaseException | None]:
            try:
                return user, self.client.list_user_tokens(str(user["id"])), None
            except Exception as exc:  # noqa: BLE001 -- handed to the collector thread, which re-raises it unless skippable
                return user, None, exc

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=TOKEN_FAN_OUT_WORKERS) as pool:
            for user, tokens, exc in pool.map(fetch, rest):
                if exc is not None:
                    if not is_skippable(exc):
                        raise exc
                    self.skipped_object_types.setdefault("user_token.users", classify_gws_failure(exc))
                    continue
                yield from self._token_objects(user, tokens or [], now)

    @staticmethod
    def _token_objects(user: dict[str, Any], tokens: list[dict[str, Any]], now: datetime) -> Iterable[RawObject]:
        user_id = str(user["id"])
        for token in tokens:
            client_id = str(token.get("clientId") or "")
            if not client_id:
                continue
            payload = dict(token)
            payload["user_id"] = user_id
            payload["user_email"] = user.get("primaryEmail")
            yield RawObject(
                object_type="user_token", provider_id=f"{user_id}:{client_id}", payload=payload, collected_at=now
            )

    def _collect_login_activity(self, now: datetime, *, since: datetime | None = None) -> Iterable[RawObject]:
        """One RawObject per Reports activity item; the normalizer keeps only
        the curated event names and drops routine successes."""
        for activity in self.client.list_login_activities(since=since):
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="login_activity",
                provider_id=f"login:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    # -------------------------------------------------------------------------
    # v0.2 additions
    # -------------------------------------------------------------------------

    def _collect_customer(self, now: datetime) -> Iterable[RawObject]:
        """Directory customer record: ID, primary domain, creation time."""
        customer = self.client.get_customer()
        cid = str(customer.get("id") or customer.get("customerDomain") or "customer")
        yield RawObject(object_type="customer", provider_id=cid, payload=customer, collected_at=now)

    def _collect_policy(self, now: datetime) -> Iterable[RawObject]:
        """Cloud Identity Policy API: one RawObject per policy object.

        Policies may be tenant-level or OU-scoped. The normalizer emits a
        subject-scoped setting when `orgUnit` is present.
        """
        for policy in self.client.list_policies():
            name = str(policy.get("name") or "")
            if not name:
                continue
            yield RawObject(
                object_type="policy",
                provider_id=name,
                payload=policy,
                collected_at=now,
            )

    def _collect_mobile_device(self, now: datetime) -> Iterable[RawObject]:
        """Mobile devices enrolled via MDM (Admin Directory)."""
        for device in self.client.list_mobile_devices():
            device_id = str(device.get("deviceId") or "")
            if not device_id:
                continue
            yield RawObject(
                object_type="mobile_device",
                provider_id=device_id,
                payload=device,
                collected_at=now,
            )

    def _collect_chromeos_device(self, now: datetime) -> Iterable[RawObject]:
        """ChromeOS devices managed by the domain (Admin Directory)."""
        for device in self.client.list_chromeos_devices():
            device_id = str(device.get("deviceId") or "")
            if not device_id:
                continue
            yield RawObject(
                object_type="chromeos_device",
                provider_id=device_id,
                payload=device,
                collected_at=now,
            )

    def _collect_alert(self, now: datetime) -> Iterable[RawObject]:
        """Alert Center: individual alert events + a count-summary object.

        Individual alerts are emitted as events by the normalizer. A synthetic
        count object (is_count_summary=True) lets the normalizer emit a
        tenant-level alert_count_setting for each severity bucket without
        accumulating all alert bodies into one RawObject.
        """
        alerts = self.client.list_alerts()
        counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for alert in alerts:
            if alert.get("deleted"):
                continue
            alert_id = str(alert.get("alertId") or "")
            if not alert_id:
                continue
            severity = str((alert.get("metadata") or {}).get("severity") or "MEDIUM").upper()
            counts[severity] = counts.get(severity, 0) + 1
            yield RawObject(
                object_type="alert",
                provider_id=f"alert:{alert_id}",
                payload=alert,
                collected_at=now,
            )
        # Synthetic count summary. Even when alerts is empty, emit the counts
        # so a zero-alert tenant still has a count setting in the graph.
        yield RawObject(
            object_type="alert",
            provider_id="alert:count",
            payload={"is_count_summary": True, "counts": counts},
            collected_at=now,
        )

    def _collect_inbound_sso_profile(self, now: datetime) -> Iterable[RawObject]:
        for profile in self.client.list_inbound_sso_profiles():
            name = str(profile.get("name") or "")
            if not name:
                continue
            yield RawObject(object_type="inbound_sso_profile", provider_id=name, payload=profile, collected_at=now)

    def _collect_inbound_sso_assignment(self, now: datetime) -> Iterable[RawObject]:
        for assignment in self.client.list_inbound_sso_assignments():
            name = str(assignment.get("name") or "")
            if not name:
                continue
            yield RawObject(object_type="inbound_sso_assignment", provider_id=name, payload=assignment, collected_at=now)

    def _collect_admin_activity(self, now: datetime, *, since: datetime | None = None) -> Iterable[RawObject]:
        """Admin Reports `admin` application — privilege grants, SSO changes, DWD access.

        Curated events keep the feed signal-dense; the normalizer maps event
        names to normalized actions. Events also feed `_collect_dwd_client`
        but DWD client synthesis happens in its own collection pass so the
        normalizer stays a pure mapping function.
        """
        for activity in self.client.list_admin_activities(since=since):
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="admin_activity",
                provider_id=f"admin:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    def _collect_drive_activity(self, now: datetime, *, since: datetime | None = None) -> Iterable[RawObject]:
        """Admin Reports `drive` application — external sharing events."""
        for activity in self.client.list_drive_activity_events(since=since):
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="drive_activity",
                provider_id=f"drive:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    def _collect_saml_activity(self, now: datetime) -> Iterable[RawObject]:
        """Admin Reports `saml` application — SAML SSO events."""
        for activity in self.client.list_saml_activities():
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="saml_activity",
                provider_id=f"saml:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    def _collect_user_accounts_activity(self, now: datetime) -> Iterable[RawObject]:
        """Admin Reports `user_accounts` application — account security events."""
        for activity in self.client.list_user_accounts_activities():
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="user_accounts_activity",
                provider_id=f"user_accounts:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    def _collect_groups_activity(self, now: datetime) -> Iterable[RawObject]:
        """Admin Reports `groups` application — group membership events."""
        for activity in self.client.list_groups_activities():
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="groups_activity",
                provider_id=f"groups:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    def _collect_mobile_activity(self, now: datetime) -> Iterable[RawObject]:
        """Admin Reports `mobile` application — device enrollment and wipe events."""
        for activity in self.client.list_mobile_activities():
            ident = sub_dict(activity, "id")
            qualifier = str(ident.get("uniqueQualifier") or "")
            stamp = str(ident.get("time") or "")
            if not qualifier and not stamp:
                continue
            yield RawObject(
                object_type="mobile_activity",
                provider_id=f"mobile:{qualifier or stamp}",
                payload=activity,
                collected_at=now,
            )

    def _collect_dwd_client(self, now: datetime) -> Iterable[RawObject]:
        """Synthetic DWD OAuth clients from admin audit AUTHORIZE_API_CLIENT_ACCESS events.

        Reads the same `admin` Reports feed as `admin_activity` and aggregates
        DWD grant events by client_id into one RawObject per OAuth client.
        REVOKE events set `revoked=True`; a client is emitted even if all
        grants have been revoked so the graph shows its prior existence.
        """
        activities = self.client.list_admin_activities()

        clients: dict[str, dict[str, Any]] = {}
        for activity in activities:
            actor = activity.get("actor") or {}
            actor_email = (actor.get("email") or "").lower()
            event_time = (activity.get("id") or {}).get("time")
            for event in activity.get("events") or []:
                event_name = (event.get("name") or "").upper()
                if event_name not in {"AUTHORIZE_API_CLIENT_ACCESS", "REVOKE_API_CLIENT_ACCESS"}:
                    continue
                params = {p.get("name"): p.get("value") for p in (event.get("parameters") or []) if p.get("name")}
                client_id = str(params.get("client_id") or params.get("CLIENT_ID") or "")
                if not client_id:
                    continue
                scopes_raw = str(params.get("api_scopes") or params.get("API_SCOPES") or "")
                scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
                bucket = clients.get(client_id)
                if bucket is None:
                    clients[client_id] = {
                        "client_id": client_id,
                        "scopes": set(scopes),
                        "revoked": event_name == "REVOKE_API_CLIENT_ACCESS",
                        "last_changed_at": event_time,
                        "last_changed_by": actor_email,
                        "event_count": 1,
                    }
                else:
                    bucket["scopes"].update(scopes)
                    bucket["event_count"] += 1
                    if event_name == "AUTHORIZE_API_CLIENT_ACCESS":
                        bucket["revoked"] = False
                    elif event_name == "REVOKE_API_CLIENT_ACCESS":
                        bucket["revoked"] = True
                    if event_time and (not bucket["last_changed_at"] or event_time > bucket["last_changed_at"]):
                        bucket["last_changed_at"] = event_time
                        bucket["last_changed_by"] = actor_email

        for client_id, bucket in clients.items():
            payload = {
                "client_id": client_id,
                "scopes": sorted(bucket["scopes"]),
                "revoked": bucket["revoked"],
                "last_changed_at": bucket["last_changed_at"],
                "last_changed_by": bucket["last_changed_by"],
                "event_count": bucket["event_count"],
            }
            yield RawObject(
                object_type="dwd_client",
                provider_id=f"dwd-client:{client_id}",
                payload=payload,
                collected_at=now,
            )
