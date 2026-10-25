# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Translates SlackClient responses into RawObjects.

Cross-cutting joins (usergroup membership, app scopes embedded on apps,
installer identity on installations) are stitched here so the normalizer
stays a pure per-object mapping.

**Gated families degrade visibly.** Everything past members and usergroups is
Enterprise Grid territory -- org roles, workspaces, app governance, Connect
orgs, shared channels, Audit Logs -- and a workspace-only bot token gets a
classified admin error for all of it. Those families skip, and record the skip
on ``skipped_object_types``, which the sync pipeline reads to downgrade the run
to PARTIAL_FAILURE and suppress deletion detection.

Skipping without recording (what this collector did ) reports an
incomplete inventory as a complete one: the run goes green, `detect_deletions`
reads the absent OAuth grants and org-role assignments as revocations, and
`/changes` fills with access removals that never happened.

Throttling is not a gate. `_request` retries `ratelimited` and then raises, and
`ratelimited` is not in SKIPPABLE_ADMIN_ERRORS, so an exhausted retry fails the
run rather than reporting an empty family.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.sdk.base import HealthCheckResult, RawObject

from kestrel_connector_slack.apps import (
    flatten_approved_app,
    installation_from_approved_app,
    scope_names,
)
from kestrel_connector_slack.client import SlackApiError, SlackClient, is_skippable_admin_error
from kestrel_connector_slack.health import check_health, classify_slack_failure

# Synthetic role ids — Slack does not expose a first-class workspace role
# catalog; owner/admin flags on users.list are the privilege signal.
ROLE_PRIMARY_OWNER = "role_primary_owner"
ROLE_OWNER = "role_owner"
ROLE_ADMIN = "role_admin"

# Common Enterprise Grid system roles (admin.roles.listAssignments).
ORG_ROLE_NAMES: dict[str, tuple[str, bool]] = {
    "Rl0A": ("Channel Admin", True),
    "Rl0C": ("Channel Manager", True),
    "Rl01": ("Org Admin", True),
    "Rl02": ("Org Owner", True),
    "Rl0D": ("Role Admin", True),
    "Rl0E": ("User Admin", True),
}

OBJECT_TYPES = [
    "team",
    "user",
    "usergroup",
    "usergroup_member",
    "admin_role",
    "role_assignment",
    "oauth_app",
    "oauth_scope",
    "oauth_grant",
    "workspace",
    "org_role",
    "org_role_assignment",
    "restricted_app",
    "app_request",
    "external_team",
    "channel",
    "shared_channel",
    "anomaly_allowlist",
    "user_session_setting",
    "audit_log",
    # Release C — Enterprise depth families.
    "sso_policy",
    "information_barrier",
    "workflow",
    "channel_retention",
    "invite_request",
]

# Channel membership is one call per channel, so it is read only where it
# answers a question -- private and externally shared channels -- and only up
# to this many channels per run; past the cap the run reports reduced
# coverage rather than scanning a prefix and calling it complete.
DEFAULT_CHANNEL_MEMBERSHIP_LIMIT = 200

# Families whose absence degrades the run rather than failing it. Everything
# else -- team, users, usergroups and the owner/admin flags role_assignment is
# derived from -- is readable by any valid token, so a failure there means the
# credential is wrong and the health check is the right place to say so.
#
# These mirror `health._OPTIONAL_PROBES`: all of them need Enterprise Grid plus
# an org-installed user token with admin scopes.
OPTIONAL_OBJECT_TYPES = frozenset(
    {
        "oauth_app",
        "oauth_scope",
        "oauth_grant",
        "workspace",
        "org_role",
        "org_role_assignment",
        "restricted_app",
        "app_request",
        "external_team",
        "channel",
        "shared_channel",
        "anomaly_allowlist",
        "user_session_setting",
        "audit_log",
        # Release C families — all need Enterprise Grid + depth scopes.
        "sso_policy",
        "information_barrier",
        "workflow",
        "channel_retention",
        "invite_request",
    }
)


class SlackCollector:
    def __init__(self, client: SlackClient, *, channel_membership_limit: int = DEFAULT_CHANNEL_MEMBERSHIP_LIMIT) -> None:
        self.client = client
        self._approved_apps: list[dict[str, Any]] | None = None
        self._last_login: dict[str, int] | None = None
        self._channel_membership_limit = max(0, int(channel_membership_limit))
        # object_type / sub-family -> failure class, read by the sync pipeline.
        self.skipped_object_types: dict[str, str] = {}

    def discover(self) -> list[str]:
        return list(OBJECT_TYPES)

    def health_check(self) -> HealthCheckResult:
        return check_health(self.client)

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterable[RawObject]:
        method = getattr(self, f"_collect_{object_type}", None)
        if method is None:
            raise ValueError(f"SlackCollector does not support object_type '{object_type}'")
        try:
            if object_type == "audit_log":
                yield from self._collect_audit_log(datetime.now(UTC), since=since)
                return
            del since
            yield from method(datetime.now(UTC))
        except Exception as exc:
            if object_type in OPTIONAL_OBJECT_TYPES and is_skippable_admin_error(exc):
                self.skipped_object_types[object_type] = classify_slack_failure(exc)
                return
            raise

    def _record_skip(self, family: str, exc: BaseException) -> None:
        """Records the first skip for a sub-family.

        One gated call affects every entity it would have been made for, so the
        entry is per family rather than per entity.
        """
        self.skipped_object_types.setdefault(family, classify_slack_failure(exc))

    def _safe_list(self, family: str, fn: Callable[..., list[dict[str, Any]]], *args: Any) -> list[dict[str, Any]]:
        try:
            return list(fn(*args))
        except Exception as exc:
            if not is_skippable_admin_error(exc):
                raise
            self._record_skip(family, exc)
            return []

    def _safe_dict(self, family: str, fn: Callable[..., dict[str, Any] | None], *args: Any) -> dict[str, Any] | None:
        try:
            result = fn(*args)
        except Exception as exc:
            if not is_skippable_admin_error(exc):
                raise
            self._record_skip(family, exc)
            return None
        return result if isinstance(result, dict) else None

    def _users(self) -> list[dict[str, Any]]:
        """The directory, recording it as reduced coverage when the org-wide
        walk was gated and the client fell back to the configured workspace.

        Without the record the run went green over one workspace's users and
        `detect_deletions` tombstoned every other workspace's identities,
        memberships, role assignments and OAuth grants.
        """
        users = self.client.list_users()
        fallback = self.client.org_directory_fallback
        if fallback is not None:
            self._record_skip("user.org_directory", fallback)
        return users

    def _collect_team(self, now: datetime) -> Iterable[RawObject]:
        team = self.client.get_team()
        payload = team.get("team", team) if isinstance(team, dict) else team
        yield RawObject(
            object_type="team",
            provider_id=str(payload["id"]),
            payload=payload if isinstance(payload, dict) else {"id": str(payload)},
            collected_at=now,
        )

    def _last_login_by_user(self) -> dict[str, int]:
        """Latest sign-in timestamp per user id from Audit Logs and analytics.

        Slack's user objects carry no last-activity field -- ``updated`` is the
        profile's modification time -- so real sign-in activity has to come from
        Audit Logs, which are Enterprise Grid only. Release C additionally reads
        ``admin.analytics.getFile`` member records (``date_last_active``) and
        takes the most recent of the two sources. Gated tenants get an empty map
        and the normalizer falls back to the profile timestamp labeled as such.
        """
        if self._last_login is not None:
            return self._last_login
        latest: dict[str, int] = {}
        for entry in self._safe_list("user.last_login", self.client.list_audit_logs):
            if entry.get("action") != "user_login":
                continue
            actor = entry.get("actor") if isinstance(entry.get("actor"), dict) else {}
            user = actor.get("user") if isinstance(actor, dict) else None
            user_id = str(user.get("id") or "") if isinstance(user, dict) else ""
            stamp = entry.get("date_create")
            if not user_id or not isinstance(stamp, (int, float)):
                continue
            if int(stamp) > latest.get(user_id, 0):
                latest[user_id] = int(stamp)
        # Augment with member analytics (admin.analytics.getFile?type=member).
        # date_last_active is a date string ("2026-09-15"); convert to midnight
        # UTC unix for comparison with audit timestamps. This is an augmentation
        # of a core family: a gate is recorded like any other, and so is any
        # other failure (an export that would not decode, a throttle), because
        # losing last-active precision must never fail the directory sync.
        for record in self._analytics_records():
            user_id = str(record.get("user_id") or record.get("id") or "")
            date_str = str(record.get("date_last_active") or "")
            if not user_id or not date_str:
                continue
            try:
                parsed = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
                stamp = int(parsed.timestamp())
            except ValueError:
                continue
            if stamp > latest.get(user_id, 0):
                latest[user_id] = stamp
        self._last_login = latest
        return latest

    def _analytics_records(self) -> list[dict[str, Any]]:
        try:
            return list(self.client.get_member_analytics())
        except Exception as exc:  # noqa: BLE001 -- recorded as reduced coverage, never fatal
            self._record_skip("user.analytics", exc)
            return []

    def _collect_user(self, now: datetime) -> Iterable[RawObject]:
        last_login = self._last_login_by_user()
        for user in self._users():
            payload = dict(user)
            user_id = str(user["id"])
            if user_id in last_login:
                payload["last_login_at"] = last_login[user_id]
            yield RawObject(object_type="user", provider_id=user_id, payload=payload, collected_at=now)

    def _collect_user_session_setting(self, now: datetime) -> Iterable[RawObject]:
        """Session duration, which Slack applies per user rather than per workspace.

        Enterprise Grid + `admin.users:read`; degrades like any other admin
        family when the token cannot see it.
        """
        user_ids = [str(user["id"]) for user in self._users() if user.get("id")]
        if not user_ids:
            return
        for row in self.client.get_session_settings(user_ids):
            user_id = str(row.get("user_id") or "")
            if not user_id:
                continue
            yield RawObject(
                object_type="user_session_setting",
                provider_id=user_id,
                payload=dict(row),
                collected_at=now,
            )

    def _collect_usergroup(self, now: datetime) -> Iterable[RawObject]:
        for group in self.client.list_usergroups():
            yield RawObject(
                object_type="usergroup",
                provider_id=str(group["id"]),
                payload=group,
                collected_at=now,
            )

    def _collect_usergroup_member(self, now: datetime) -> Iterable[RawObject]:
        for group in self.client.list_usergroups():
            group_id = str(group["id"])
            for user_id in self.client.list_usergroup_users(group_id):
                yield RawObject(
                    object_type="usergroup_member",
                    provider_id=f"{group_id}:{user_id}",
                    payload={"usergroup_id": group_id, "user_id": str(user_id)},
                    collected_at=now,
                )

    def _collect_admin_role(self, now: datetime) -> Iterable[RawObject]:
        for role_id, name, privileged in (
            (ROLE_PRIMARY_OWNER, "Primary Owner", True),
            (ROLE_OWNER, "Owner", True),
            (ROLE_ADMIN, "Admin", True),
        ):
            yield RawObject(
                object_type="admin_role",
                provider_id=role_id,
                payload={"id": role_id, "name": name, "is_privileged": privileged},
                collected_at=now,
            )

    def _collect_role_assignment(self, now: datetime) -> Iterable[RawObject]:
        for user in self._users():
            if user.get("deleted") or user.get("is_bot"):
                continue
            user_id = str(user["id"])
            if user.get("is_primary_owner"):
                role_id = ROLE_PRIMARY_OWNER
            elif user.get("is_owner"):
                role_id = ROLE_OWNER
            elif user.get("is_admin"):
                role_id = ROLE_ADMIN
            else:
                continue
            yield RawObject(
                object_type="role_assignment",
                provider_id=f"{user_id}:{role_id}",
                payload={"user_id": user_id, "role_id": role_id},
                collected_at=now,
            )

    def _approved_app_payloads(self) -> list[dict[str, Any]]:
        if self._approved_apps is not None:
            return self._approved_apps
        try:
            raw = self.client.list_approved_apps()
        except Exception as exc:
            if is_skippable_admin_error(exc):
                # One gated call, three affected object types (oauth_app,
                # oauth_scope, oauth_grant) -- record the call, not each of them.
                self._record_skip("oauth_app.approved", exc)
                self._approved_apps = []
                return self._approved_apps
            raise
        self._approved_apps = [flatten_approved_app(item) for item in raw]
        return self._approved_apps

    def _collect_oauth_app(self, now: datetime) -> Iterable[RawObject]:
        for app in self._approved_app_payloads():
            app_id = str(app.get("app_id") or "")
            if not app_id:
                continue
            yield RawObject(object_type="oauth_app", provider_id=app_id, payload=app, collected_at=now)

    def _collect_oauth_scope(self, now: datetime) -> Iterable[RawObject]:
        for app in self._approved_app_payloads():
            app_id = str(app.get("app_id") or "")
            if not app_id:
                continue
            for scope_name, slack_sensitive in scope_names(app):
                payload: dict[str, Any] = {"app_id": app_id, "scope_name": scope_name}
                if slack_sensitive is not None:
                    payload["is_sensitive"] = slack_sensitive
                yield RawObject(
                    object_type="oauth_scope",
                    provider_id=f"{app_id}:{scope_name}",
                    payload=payload,
                    collected_at=now,
                )

    def _collect_oauth_grant(self, now: datetime) -> Iterable[RawObject]:
        """Installer grants derived from the approved-app record.

        Slack has no installations API: the approved app names its installer
        (``last_resolved_by`` live, ``installer_user_id`` in fixtures), and
        ``admin.apps.activities.list`` supplies last-active for the unused-app
        check. That is the complete picture, not a fallback.
        """
        activity_by_app: dict[str, str] = {}
        try:
            for activity in self.client.list_app_activities():
                app_id = str(activity.get("app_id") or "")
                last_active = activity.get("date_last_active") or activity.get("last_active")
                if app_id and last_active:
                    activity_by_app[app_id] = str(last_active)
        except Exception as exc:
            if not is_skippable_admin_error(exc):
                raise
            # Without this "no last-active" and "could not read last-active"
            # were indistinguishable, and the unused-app check went quiet.
            self._record_skip("oauth_grant.activities", exc)

        installations: list[dict[str, Any]] = []
        for app in self._approved_app_payloads():
            grant = installation_from_approved_app(app)
            if grant is not None:
                installations.append(grant)
        seen: set[str] = set()
        for installation in installations:
            app_id = str(installation.get("app_id") or "")
            user_id = str(installation.get("user_id") or "")
            if not app_id or not user_id:
                continue
            provider_id = f"{app_id}:{user_id}"
            if provider_id in seen:
                continue
            seen.add(provider_id)
            enriched = dict(installation)
            if app_id in activity_by_app and not enriched.get("last_active_at"):
                enriched["last_active_at"] = activity_by_app[app_id]
            yield RawObject(
                object_type="oauth_grant",
                provider_id=provider_id,
                payload=enriched,
                collected_at=now,
            )

    def _collect_workspace(self, now: datetime) -> Iterable[RawObject]:
        for workspace in self.client.list_workspaces():
            team_id = str(workspace.get("id") or "")
            if not team_id:
                continue
            settings = self._safe_dict("workspace.settings", self.client.get_workspace_settings, team_id) or {}
            payload = {**workspace, **{k: v for k, v in settings.items() if k not in workspace}}
            yield RawObject(
                object_type="workspace",
                provider_id=team_id,
                payload=payload,
                collected_at=now,
            )

    def _collect_org_role(self, now: datetime) -> Iterable[RawObject]:
        seen: set[str] = set()
        for assignment in self.client.list_role_assignments():
            role_id = str(assignment.get("role_id") or "")
            if not role_id or role_id in seen:
                continue
            seen.add(role_id)
            name, privileged = ORG_ROLE_NAMES.get(role_id, (f"Org role {role_id}", True))
            yield RawObject(
                object_type="org_role",
                provider_id=role_id,
                payload={"id": role_id, "name": name, "is_privileged": privileged},
                collected_at=now,
            )

    def _collect_org_role_assignment(self, now: datetime) -> Iterable[RawObject]:
        for assignment in self.client.list_role_assignments():
            role_id = str(assignment.get("role_id") or "")
            user_id = str(assignment.get("user_id") or "")
            entity_id = str(assignment.get("entity_id") or "")
            if not role_id or not user_id:
                continue
            provider_id = f"{user_id}:{role_id}"
            if entity_id:
                provider_id = f"{provider_id}:{entity_id}"
            yield RawObject(
                object_type="org_role_assignment",
                provider_id=provider_id,
                payload={
                    "user_id": user_id,
                    "role_id": role_id,
                    "entity_id": entity_id or None,
                    "date_create": assignment.get("date_create"),
                },
                collected_at=now,
            )

    def _collect_restricted_app(self, now: datetime) -> Iterable[RawObject]:
        for app in self.client.list_restricted_apps():
            nested_raw = app.get("app")
            nested = nested_raw if isinstance(nested_raw, dict) else app
            app_id = str(nested.get("id") or app.get("app_id") or "")
            if not app_id:
                continue
            payload = flatten_approved_app(app) if "app" in app or "scopes" in app else dict(app)
            payload["app_id"] = app_id
            payload["is_restricted"] = True
            yield RawObject(
                object_type="restricted_app",
                provider_id=app_id,
                payload=payload,
                collected_at=now,
            )

    def _collect_app_request(self, now: datetime) -> Iterable[RawObject]:
        for request in self.client.list_app_requests():
            request_id = str(
                request.get("id")
                or request.get("app_request_id")
                or f"{request.get('app', {}).get('id', 'app')}:{request.get('user_id', 'user')}"
            )
            yield RawObject(
                object_type="app_request",
                provider_id=request_id,
                payload=request,
                collected_at=now,
            )

    def _collect_external_team(self, now: datetime) -> Iterable[RawObject]:
        for org in self.client.list_external_teams():
            team_id = str(org.get("team_id") or org.get("id") or "")
            if not team_id:
                continue
            yield RawObject(
                object_type="external_team",
                provider_id=team_id,
                payload=org,
                collected_at=now,
            )

    def _collect_channel(self, now: datetime) -> Iterable[RawObject]:
        """Channel inventory with membership where it matters.

        Membership is read for private and externally shared channels, which
        is where a guest or an outside organization is a finding; public
        channels are open to every member by definition.
        """
        channels = self.client.list_channels()
        directory = {str(u.get("id")) for u in self._users()}
        needs_members = [
            c
            for c in channels
            if c.get("is_private") or c.get("is_ext_shared") or c.get("is_shared") or c.get("is_org_shared")
        ]
        read_members = needs_members[: self._channel_membership_limit]
        if len(needs_members) > len(read_members):
            self.skipped_object_types.setdefault(
                "channel.membership.truncated",
                f"channel_membership_limit={self._channel_membership_limit}",
            )
        wanted = {str(c.get("id")) for c in read_members}
        for channel in channels:
            channel_id = str(channel.get("id") or "")
            if not channel_id:
                continue
            payload = dict(channel)
            if channel_id in wanted:
                member_ids = self._safe_list(
                    "channel.members", lambda cid: [{"id": m} for m in self.client.list_channel_members(cid)], channel_id
                )
                payload["member_ids"] = [str(m["id"]) for m in member_ids if str(m.get("id")) in directory]
            yield RawObject(object_type="channel", provider_id=channel_id, payload=payload, collected_at=now)

    def _collect_shared_channel(self, now: datetime) -> Iterable[RawObject]:
        for channel in self.client.list_shared_channels():
            channel_id = str(channel.get("id") or channel.get("channel_id") or "")
            if not channel_id:
                continue
            yield RawObject(
                object_type="shared_channel",
                provider_id=channel_id,
                payload=channel,
                collected_at=now,
            )

    def _collect_anomaly_allowlist(self, now: datetime) -> Iterable[RawObject]:
        payload = self.client.get_anomaly_allowlist()
        if not isinstance(payload, dict):
            return
        # Fixture may store a bare allowlist object; live wraps under trusted_* keys.
        yield RawObject(
            object_type="anomaly_allowlist",
            provider_id="anomaly_allowlist",
            payload=payload,
            collected_at=now,
        )

    def _collect_audit_log(self, now: datetime, *, since: datetime | None = None) -> Iterable[RawObject]:
        for entry in self.client.list_audit_logs(since=since):
            provider_id = str(entry.get("id") or "")
            if not provider_id:
                continue
            yield RawObject(
                object_type="audit_log",
                provider_id=provider_id,
                payload=entry,
                collected_at=now,
            )

    # ------------------------------------------------------------------ #
    # Release C — Enterprise depth families                                #
    # ------------------------------------------------------------------ #

    def _collect_sso_policy(self, now: datetime) -> Iterable[RawObject]:
        """SSO policy entities from admin.auth.policy.getEntities.

        Emits one row per policy type returned.  The normalizer counts the
        entity list to derive ``sso_bypass_count``.
        """
        result = self._safe_dict("sso_policy", self.client.get_auth_policy)
        if result is None:
            return
        # The API may return a list of policies under ``policies`` or a single
        # policy dict; normalise to a list.
        policies = result.get("policies") or []
        if isinstance(policies, list) and policies:
            for policy in policies:
                if not isinstance(policy, dict):
                    continue
                policy_type = str(policy.get("policy_type") or policy.get("type") or "unknown")
                yield RawObject(
                    object_type="sso_policy",
                    provider_id=f"sso-policy-{policy_type}",
                    payload=policy,
                    collected_at=now,
                )
        else:
            # Single-policy response shape.
            policy_type = str(result.get("policy_type") or result.get("type") or "sso")
            yield RawObject(
                object_type="sso_policy",
                provider_id=f"sso-policy-{policy_type}",
                payload=result,
                collected_at=now,
            )

    def _collect_information_barrier(self, now: datetime) -> Iterable[RawObject]:
        """Information barriers (admin.barriers.list).

        Each active barrier yields one setting row.  The absence of any row
        (empty list) is the signal for ``slack-information-barrier-missing``.
        """
        for barrier in self.client.list_information_barriers():
            barrier_id = str(barrier.get("id") or barrier.get("barrier_id") or "")
            if not barrier_id:
                continue
            yield RawObject(
                object_type="information_barrier",
                provider_id=barrier_id,
                payload=barrier,
                collected_at=now,
            )

    def _collect_workflow(self, now: datetime) -> Iterable[RawObject]:
        """Workflow inventory (admin.workflows.search).

        Workflows can share data externally or run with broad permissions;
        each one becomes a resource so governance policies can evaluate them.
        """
        for workflow in self.client.list_workflows():
            workflow_id = str(workflow.get("id") or workflow.get("workflow_id") or "")
            if not workflow_id:
                continue
            yield RawObject(
                object_type="workflow",
                provider_id=workflow_id,
                payload=workflow,
                collected_at=now,
            )

    def _collect_channel_retention(self, now: datetime) -> Iterable[RawObject]:
        """Per-channel custom retention policies.

        Only reads private and externally shared channels (the same set that
        gets membership reads) up to ``channel_membership_limit`` channels;
        past that the coverage is honestly truncated.  Public channels use the
        workspace default, which is a separate settings check.
        """
        channels = self.client.list_channels()
        candidates = [c for c in channels if c.get("is_private") or c.get("is_ext_shared") or c.get("is_shared")][
            : self._channel_membership_limit
        ]
        if len(candidates) < sum(1 for c in channels if c.get("is_private") or c.get("is_ext_shared") or c.get("is_shared")):
            self.skipped_object_types.setdefault(
                "channel_retention.truncated",
                f"channel_membership_limit={self._channel_membership_limit}",
            )
        for channel in candidates:
            channel_id = str(channel.get("id") or "")
            if not channel_id:
                continue
            try:
                result = self._safe_dict(
                    "channel_retention",
                    self.client.get_channel_retention,
                    channel_id,
                )
            except SlackApiError as exc:
                if exc.error != "channel_not_found":
                    raise
                # The channel went away between the listing and this call.
                continue
            if result is None:
                continue
            # Only emit when the channel has an actual custom retention policy.
            if not (result.get("duration") or result.get("retention_duration") or result.get("type")):
                continue
            yield RawObject(
                object_type="channel_retention",
                provider_id=f"retention:{channel_id}",
                payload={**result, "channel_id": channel_id},
                collected_at=now,
            )

    def _collect_invite_request(self, now: datetime) -> Iterable[RawObject]:
        """Pending invite requests (admin.invites.invited.list).

        Each request that has not been approved or denied becomes a row.
        The normalizer converts each row to a count-contribution setting so
        ``slack-stale-invite-request`` can report days pending.
        """
        for request in self.client.list_invite_requests():
            request_id = str(request.get("id") or request.get("invite_id") or request.get("email") or "")
            if not request_id:
                continue
            # Compute days pending from date_create if present.
            payload = dict(request)
            date_create = request.get("date_create") or request.get("date_created")
            if isinstance(date_create, (int, float)):
                days = int((datetime.now(UTC).timestamp() - date_create) / 86400)
                payload["days_pending"] = days
            yield RawObject(
                object_type="invite_request",
                provider_id=request_id,
                payload=payload,
                collected_at=now,
            )
