# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Maps GitHub RawObjects into Kestrel NormalizedObjects.

Entity references between normalized objects (e.g. a grant's resource, or a
group membership's identity) are expressed as provider ids in `_ref`
attributes and in NormalizedRelationship.source_ref/target_ref -- Kestrel ids
don't exist yet at normalize time, so resolution to real foreign keys happens
in the graph writer / upsert layer once every object in the run has been
normalized.

Organization payloads emit tenant `setting` rows for org-level
security/access configuration. The ApplicationInstance row itself is still
created out of band when a connector instance is configured.

Audit-log entries emit normalized `event` rows for deterministic
activity policies.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kestrel.connectors.sdk.base import NormalizedObject, NormalizedRelationship, RawObject
from kestrel.connectors.settings_emit import setting_object, settings_from_mapping

ORG_ADMIN_ROLE_PROVIDER_ID = "organization_admin"

_ACTION_CATEGORIES: dict[str, str] = {
    "privilege.grant": "privilege",
    "privilege.revoke": "privilege",
    "privilege.external": "privilege",
    "service_account.escalate": "privilege",
    "access.grant": "access",
    "access.revoke": "access",
    "group.member.add": "access",
    "group.member.remove": "access",
    "mfa.disable": "mfa",
    "mfa.enforce": "mfa",
    "oauth.sensitive_consent": "oauth",
    "oauth.app.install": "oauth",
    "oauth.app.revoke": "oauth",
    "oauth.scope.expand": "oauth",
    "token.grant": "oauth",
    "identity.add": "identity",
    "identity.deactivate": "identity",
    "identity.guest": "identity",
    "dormant.reactivate": "identity",
    "sharing.external": "sharing",
    "branch_protection.disable": "config",
    "webhook.create": "config",
    "deploy_key.create": "config",
    "sso.change": "config",
    "config.change": "config",
    "resource.create": "resource",
    "resource.delete": "resource",
}

# GitHub audit action -> normalized Kestrel action.
#
# Curated, not exhaustive. The audit log carries hundreds of action types and
# most are product telemetry, not security posture; mapping them all would push
# real signal out of both the event-policy window and the `/changes` actor
# overlay. Two families are deliberately absent:
#
#   * Git events (`git.clone`, `git.push`, `git.fetch`) -- enormous volume, and
#     `include=web` means they are not even collected.
#   * Code-scanning, Dependabot, and secret-scanning *alerts* -- that is ASPM,
#     which `docs/connectors.md` puts out of scope. GHAS
#     *enablement* is posture and is collected as settings instead.
#
# The normalized vocabulary is shared with Okta and Slack wherever the concept
# is shared, so a cross-app event policy does not need per-provider branches.
_GITHUB_ACTION_TO_KESTREL: dict[str, str] = {
    # -- org membership and privilege --------------------------------------
    "org.add_member": "identity.add",
    "org.remove_member": "identity.deactivate",
    "org.remove_outside_collaborator": "access.revoke",
    "org.add_outside_collaborator": "identity.guest",
    "org.reactivate_member": "dormant.reactivate",
    "org.invite_member_to_enterprise": "identity.add",
    "org.deactivate_member": "identity.deactivate",
    "org.restore_member": "dormant.reactivate",
    # -- two-factor ---------------------------------------------------------
    "org.disable_member_two_factor": "mfa.disable",
    "org.disable_two_factor_requirement": "mfa.disable",
    "org.enable_two_factor_requirement": "mfa.enforce",
    # -- teams --------------------------------------------------------------
    "team.add_member": "group.member.add",
    "team.remove_member": "group.member.remove",
    "team.add_repository": "access.grant",
    "team.remove_repository": "access.revoke",
    "team.change_parent_team": "config.change",
    "team.create": "access.grant",
    "team.destroy": "access.revoke",
    "team.update": "config.change",
    # -- repository access --------------------------------------------------
    "repo.add_member": "access.grant",
    "repo.remove_member": "access.revoke",
    "repo.create": "resource.create",
    "repo.destroy": "resource.delete",
    "repo.transfer": "config.change",
    "repo.archived": "config.change",
    "repo.create_from_template": "resource.create",
    "repo.change_merge_setting": "config.change",
    # -- branch protection and rulesets -------------------------------------
    "protected_branch.destroy": "branch_protection.disable",
    "protected_branch.policy_override": "branch_protection.disable",
    "protected_branch.dismiss_stale_reviews": "branch_protection.disable",
    "protected_branch.update_admin_enforced": "branch_protection.disable",
    "protected_branch.update_require_code_owner_review": "branch_protection.disable",
    "protected_branch.create": "config.change",
    "protected_branch.update": "config.change",
    "repository_ruleset.destroy": "branch_protection.disable",
    "repository_ruleset.update": "config.change",
    "repository_ruleset.create": "config.change",
    "org_ruleset.create": "config.change",
    "org_ruleset.update": "config.change",
    "org_ruleset.destroy": "branch_protection.disable",
    # -- supply chain: webhooks, keys, apps, tokens --------------------------
    "hook.create": "webhook.create",
    "hook.config_changed": "webhook.create",
    "hook.destroy": "config.change",
    "repo.create_actions_secret": "config.change",
    "org.create_actions_secret": "config.change",
    "repo.register_self_hosted_runner": "config.change",
    "org.register_self_hosted_runner": "config.change",
    "deploy_key.create": "deploy_key.create",
    "deploy_key.delete": "config.change",
    "integration_installation.create": "oauth.app.install",
    "integration_installation.repositories_added": "oauth.scope.expand",
    "integration_installation.repositories_removed": "access.revoke",
    "integration_installation.update": "config.change",
    "integration_installation.destroy": "oauth.app.revoke",
    "oauth_application.create": "oauth.app.install",
    "oauth_application.destroy": "oauth.app.revoke",
    "oauth_authorization.create": "oauth.sensitive_consent",
    "org.authorize_oauth_app": "oauth.sensitive_consent",
    "org.revoke_oauth_app": "oauth.app.revoke",
    "org.delete_oauth_app": "oauth.app.revoke",
    "personal_access_token.access_granted": "token.grant",
    "personal_access_token.access_revoked": "access.revoke",
    "personal_access_token.approve": "token.grant",
    "personal_access_token.deny": "config.change",
    "personal_access_token.revoke": "access.revoke",
    "personal_access_token.request_created": "token.grant",
    # -- SSO, SCIM, and org-wide configuration -------------------------------
    "org.saml_disabled": "sso.change",
    "org.saml_enabled": "sso.change",
    "org.disable_saml": "sso.change",
    "org.enable_saml": "sso.change",
    "org.update_saml_provider_settings": "sso.change",
    "org.disable_oauth_app_restrictions": "config.change",
    "org.enable_oauth_app_restrictions": "config.change",
    "org.update_default_repository_permission": "config.change",
    "org.update_member_repository_creation_permission": "config.change",
    "org.change_repository_visibility": "config.change",
    "org.ip_allow_list.disable": "config.change",
    "org.ip_allow_list.enable": "config.change",
    "org.ip_allow_list_entry.destroy": "config.change",
    "org.ip_allow_list_entry.create": "config.change",
    "org.ip_allow_list_entry.update": "config.change",
    "org.advanced_security_disabled": "config.change",
    "org.advanced_security_enabled": "config.change",
    "org.advanced_security_policy_selected_member_disabled": "config.change",
    "repo.advanced_security_disabled": "config.change",
    "repo.advanced_security_enabled": "config.change",
    "org.disable_secret_scanning": "config.change",
    "org.enable_secret_scanning": "config.change",
    "repo.secret_scanning_push_protection_disabled": "config.change",
    "repo.secret_scanning_push_protection_enabled": "config.change",
    "repo.secret_scanning_enabled": "config.change",
    "repo.secret_scanning_disabled": "config.change",
    "repo.enable_vulnerability_alerts": "config.change",
    "repo.disable_vulnerability_alerts": "config.change",
    # -- Actions permissions and OIDC ------------------------------------
    "org.actions_permission_update": "config.change",
    "repo.actions_permission_update": "config.change",
    "oidc.create_provider": "identity.add",
    "oidc.update_provider": "config.change",
    "oidc.delete_provider": "config.change",
    "actions.update_actions_secret": "config.change",
    "actions.remove_actions_secret": "config.change",
    # -- Copilot ---------------------------------------------------------
    "copilot.enable": "config.change",
    "copilot.disable": "config.change",
    "copilot.seat_assignment_added": "access.grant",
    "copilot.seat_assignment_removed": "access.revoke",
    "copilot.seat_assignment_created": "access.grant",
    "copilot.seat_assignment_cancelled": "access.revoke",
    "copilot.seat_cancelled": "access.revoke",
    "copilot.seat_add": "access.grant",
    "copilot.seat_remove": "access.revoke",
    # -- Codespaces ------------------------------------------------------
    "codespaces.create": "resource.create",
    "codespaces.delete": "resource.delete",
    "codespaces.export": "sharing.external",
    "codespaces.update": "config.change",
    # -- Pages -----------------------------------------------------------
    "pages.create": "resource.create",
    "pages.delete": "resource.delete",
    "pages.update": "config.change",
    # -- Packages --------------------------------------------------------
    "packages.package_version_published": "resource.create",
    "packages.package_version_deleted": "resource.delete",
    "packages.package_private": "config.change",
    "packages.package_public": "sharing.external",
    "packages.package_transfer": "config.change",
    "packages.package_deleted": "resource.delete",
    # -- Code security configurations ------------------------------------
    "code_security_configuration.create": "config.change",
    "code_security_configuration.update": "config.change",
    "code_security_configuration.delete": "config.change",
    "code_security_configuration.attach": "config.change",
    "code_security_configuration.detach": "config.change",
    "code_security_configuration.set_as_default": "config.change",
    # -- Dependabot ------------------------------------------------------
    "dependabot.enable": "config.change",
    "dependabot.disable": "config.change",
    "repository_vulnerability_alert.create": "config.change",
    "repository_vulnerability_alert.dismiss": "config.change",
    "repository_vulnerability_alert.reintroduce": "config.change",
    # -- Audit log streaming ---------------------------------------------
    "audit_log_streaming.create": "config.change",
    "audit_log_streaming.update": "config.change",
    "audit_log_streaming.destroy": "config.change",
    "audit_log_streaming.check": "config.change",
    # -- Custom roles ----------------------------------------------------
    "org.create_repository_role": "config.change",
    "org.update_repository_role": "config.change",
    "org.delete_repository_role": "config.change",
    "org_role.create": "config.change",
    "org_role.update": "config.change",
    "org_role.delete": "config.change",
    "org_role.assign": "access.grant",
    "org_role.revoke": "access.revoke",
    # -- Enterprise ------------------------------------------------------
    "enterprise.add_member": "identity.add",
    "enterprise.remove_member": "identity.deactivate",
    "enterprise.add_organization": "access.grant",
    "enterprise.remove_organization": "access.revoke",
    "enterprise.update_member_repository_creation_permission": "config.change",
    "enterprise.set_actions_permissions_policy": "config.change",
    "enterprise.disable_two_factor_requirement": "mfa.disable",
    "enterprise.enable_two_factor_requirement": "mfa.enforce",
    "enterprise.update_saml_provider_settings": "sso.change",
    "business.add_organization": "access.grant",
    "business.remove_organization": "access.revoke",
    "business.set_actions_permissions_policy": "config.change",
    # -- Billing ---------------------------------------------------------
    "billing.update_plan": "config.change",
    # -- Org rename and transfer -----------------------------------------
    "org.rename": "config.change",
}

# Repository visibility transitions are the one action whose meaning depends on
# its payload rather than its name: `repo.access` covers both directions.
_VISIBILITY_ACTION = "repo.access"


# -- org security surface ------------------------------------------

# Permissions that let an installed App change code, configuration, or access.
# GitHub App permissions are `{name: "read"|"write"|"admin"}` rather than OAuth
# scope strings, so sensitivity is the *level*, not the name.
_SENSITIVE_APP_PERMISSION_LEVELS = frozenset({"write", "admin"})
# ...except these, where even read access is a credential-exposure surface.
_SENSITIVE_APP_PERMISSION_NAMES = frozenset(
    {
        "secrets",
        "organization_secrets",
        "actions",
        "administration",
        "organization_administration",
        "members",
        "organization_hooks",
        "repository_hooks",
        "workflows",
        "contents",
    }
)


def _app_permission_is_sensitive(name: str, level: str) -> bool:
    return level in _SENSITIVE_APP_PERMISSION_LEVELS or name in _SENSITIVE_APP_PERMISSION_NAMES


_ACTIONS_PERMISSION_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "enabled_repositories",
        "security",
        "Repositories allowed to run Actions",
        "string",
        "all, none, or selected.",
    ),
    (
        "allowed_actions",
        "security",
        "Actions allowed to run",
        "string",
        "all, local_only, or selected. `all` permits any third-party action.",
    ),
    (
        "default_workflow_permissions",
        "security",
        "Default GITHUB_TOKEN permissions",
        "string",
        "`write` gives every workflow write access to its repository by default.",
    ),
    (
        "can_approve_pull_request_reviews",
        "security",
        "Workflows can approve pull requests",
        "boolean",
        "Allows a workflow to satisfy its own review requirement.",
    ),
]


def _permission_level(permissions: dict[str, Any]) -> str:
    if permissions.get("admin"):
        return "admin"
    if permissions.get("push") or permissions.get("maintain"):
        return "write"
    return "read"


# Words that, in a repository name or topic, say the contents are worth more
# than average: production systems, secrets, money, and customer data. Broad on
# purpose -- this marks a repository as *worth reviewing*, and an operator can
# override either way from the resource page.
_SENSITIVE_NAME_MARKERS: tuple[str, ...] = (
    "secret",
    "vault",
    "credential",
    "key",
    "prod",
    "production",
    "infra",
    "infrastructure",
    "terraform",
    "deploy",
    "payment",
    "billing",
    "finance",
    "customer",
    "pii",
    "security",
    "auth",
    "identity",
)


def _repository_sensitivity(repo: dict[str, Any]) -> tuple[bool | None, list[str]]:
    """Whether a repository is worth treating as sensitive, and why.

    Deliberately a small, explainable heuristic rather than a score: a private
    repository whose name or topics name production, secrets, money, or
    customer data. Public repositories are never sensitive by this rule --
    their contents are already published, and treating them as sensitive would
    bury the private ones. Returns ``(None, [])`` when nothing is known, so a
    policy can tell "not sensitive" from "never assessed".
    """
    visibility = _visibility(repo)
    if visibility == "public":
        return False, ["public repository"]
    haystack = {str(repo.get("name") or "").casefold()}
    haystack.update(str(topic).casefold() for topic in (repo.get("topics") or []))
    matched = sorted({marker for marker in _SENSITIVE_NAME_MARKERS for text in haystack if marker in text})
    if matched:
        return True, [f"name or topic matches {marker!r}" for marker in matched]
    return None, []


def _visibility(repo: dict[str, Any]) -> str:
    if repo.get("visibility") == "internal":
        return "internal"
    return "public" if not repo.get("private", True) else "private"


_ORG_SETTING_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "two_factor_requirement_enabled",
        "security",
        "Require two-factor authentication",
        "boolean",
        "Whether organization members must enable 2FA.",
    ),
    (
        "default_repository_permission",
        "access",
        "Default repository permission",
        "string",
        "Base permission for organization members on new repositories.",
    ),
    (
        "members_can_create_repositories",
        "access",
        "Members can create repositories",
        "boolean",
        None,
    ),
    (
        "members_can_create_public_repositories",
        "sharing",
        "Members can create public repositories",
        "boolean",
        None,
    ),
    (
        "members_can_create_private_repositories",
        "access",
        "Members can create private repositories",
        "boolean",
        "When false, only owners can create private repositories.",
    ),
    (
        "members_can_fork_private_repositories",
        "sharing",
        "Members can fork private repositories",
        "boolean",
        None,
    ),
    (
        "web_commit_signoff_required",
        "security",
        "Web commit signoff required",
        "boolean",
        "Requires committers to sign off on commits made through the GitHub web interface.",
    ),
    (
        "members_can_create_pages",
        "sharing",
        "Members can create GitHub Pages sites",
        "boolean",
        None,
    ),
    (
        "members_can_create_public_pages",
        "sharing",
        "Members can create public GitHub Pages sites",
        "boolean",
        None,
    ),
]


def _looks_like_email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if "@" in text and " " not in text else None


def _member_email(payload: dict[str, Any]) -> str | None:
    """The address a member signs in with, in order of trust.

    A profile email is the person's own claim; a SAML NameID or SCIM username
    is what the identity provider asserted, so it wins when present and is
    address-shaped (some IdPs assert an opaque id, which must not be mistaken
    for an email).
    """
    for candidate in (payload.get("saml_name_id"), payload.get("scim_username"), payload.get("email")):
        email = _looks_like_email(candidate)
        if email:
            return email
    return None


class GitHubNormalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        # The org security surface normalizes through module-level
        # functions rather than methods: none of them cross-reference another
        # object type, so none of them need instance state, and keeping them
        # out of the class keeps this dispatch honest about which do.
        module_level = _MODULE_NORMALIZERS.get(object_type)
        if module_level is not None:
            return module_level(raw)
        method = getattr(self, f"_normalize_{object_type}", None)
        if method is None:
            raise ValueError(f"GitHubNormalizer does not support object_type '{object_type}'")
        return method(raw)

    def _normalize_organization(self, raw: RawObject) -> list[NormalizedObject]:
        return settings_from_mapping(raw.payload, _ORG_SETTING_SPECS)

    def _normalize_member(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        # Prefer profile name/email when present (fixture or live org-member
        # enrichment). Live GitHub often omits email — leave null rather than
        # inventing noreply addresses (cross-app correlation).
        display_name = payload.get("name") or payload.get("display_name") or payload.get("login")
        email = _member_email(payload)
        # Tri-state: the collector sets `two_factor_disabled` to None when the
        # credential could not read the 2FA filter (it needs org ownership).
        # Unknown must stay unknown -- coercing it to "enrolled" would hide real
        # exposure, and coercing it to "not enrolled" would open a finding on
        # every member.
        two_factor_disabled = payload.get("two_factor_disabled")
        mfa_enabled = None if two_factor_disabled is None else not two_factor_disabled

        identity = NormalizedObject(
            kind="identity",
            provider_id=raw.provider_id,
            attributes={
                "identity_type": "user",
                "display_name": display_name,
                "email": email,
                # GitHub Cloud exposes no per-member disabled state on
                # /orgs/{org}/members. GHES sends `suspended_at`, so honor it
                # where present rather than asserting everyone is active.
                "is_disabled": bool(payload.get("suspended_at")),
                "is_external": False,
                "mfa_enabled": mfa_enabled,
                "created_at_source": payload.get("created_at"),
            },
            raw_source=payload,
        )
        objects = [identity]

        if payload.get("org_role") == "admin":
            identity.relationships.append(
                NormalizedRelationship(
                    edge_type="assigned_role",
                    source_ref=raw.provider_id,
                    target_ref=ORG_ADMIN_ROLE_PROVIDER_ID,
                    access_path="direct",
                )
            )
            objects.append(
                NormalizedObject(
                    kind="role",
                    provider_id=ORG_ADMIN_ROLE_PROVIDER_ID,
                    attributes={"name": "organization_admin", "is_privileged": True},
                    raw_source={"synthetic": True, "source_login": payload["login"]},
                )
            )
            # The graph edge above is what policies read for role membership,
            # but the assignment also needs a grant row so that gaining or
            # losing org admin is visible to change detection, which diffs
            # relationship rows rather than the derived graph. Matches how
            # Okta and Google Workspace emit role assignments.
            objects.append(
                NormalizedObject(
                    kind="grant",
                    provider_id=f"org-admin:{raw.provider_id}",
                    attributes={
                        "granted_via": "role_assignment",
                        "identity_ref": raw.provider_id,
                        "role_ref": ORG_ADMIN_ROLE_PROVIDER_ID,
                    },
                    raw_source={"synthetic": True, "source_login": payload["login"]},
                )
            )
        return objects

    def _normalize_team(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="group",
                provider_id=raw.provider_id,
                attributes={"name": payload["name"], "description": payload.get("description")},
                raw_source=payload,
            )
        ]

    def _normalize_team_membership(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        team_id = str(payload["team_id"])
        member_id = str(payload["member"]["id"])
        return [
            NormalizedObject(
                kind="group_membership",
                provider_id=raw.provider_id,
                attributes={"group_ref": team_id, "identity_ref": member_id},
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="member_of",
                        source_ref=member_id,
                        target_ref=team_id,
                        access_path="direct",
                    )
                ],
            )
        ]

    def _normalize_team_repo_permission(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        team_id = str(payload["team_id"])
        repo = payload["repo"]
        repo_id = str(repo["id"])
        permission_level = _permission_level(repo.get("permissions", {}))
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "group",
                    "resource_ref": repo_id,
                    "source_group_ref": team_id,
                    "permission_level": permission_level,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="can_access",
                        source_ref=team_id,
                        target_ref=repo_id,
                        access_path="inherited_group",
                        properties={"permission_level": permission_level},
                    )
                ],
            )
        ]

    def _normalize_repository(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        sensitive, reasons = _repository_sensitivity(payload)
        return [
            NormalizedObject(
                kind="resource",
                provider_id=raw.provider_id,
                attributes={
                    "resource_type": "repository",
                    "name": payload["name"],
                    "visibility": _visibility(payload),
                    "is_sensitive": sensitive,
                    "config": {
                        "sensitivity_reasons": reasons,
                        "sensitivity_source": "heuristic",
                        "archived": bool(payload.get("archived")),
                        "default_branch": payload.get("default_branch"),
                        "topics": sorted(str(t) for t in (payload.get("topics") or [])),
                    },
                },
                raw_source=payload,
            )
        ]

    def _normalize_repo_collaborator(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        repo = payload["repo"]
        collaborator = payload["collaborator"]
        repo_id = str(repo["id"])
        identity_id = str(collaborator["id"])
        permission_level = _permission_level(collaborator.get("permissions", {}))
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "direct",
                    "resource_ref": repo_id,
                    "identity_ref": identity_id,
                    "permission_level": permission_level,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="can_access",
                        source_ref=identity_id,
                        target_ref=repo_id,
                        access_path="direct",
                        properties={"permission_level": permission_level},
                    )
                ],
            )
        ]

    def _normalize_outside_collaborator(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="identity",
                provider_id=raw.provider_id,
                attributes={
                    "identity_type": "external_identity",
                    "display_name": payload["login"],
                    "email": None,
                    "is_disabled": False,
                    "is_external": True,
                    "mfa_enabled": None,
                },
                raw_source=payload,
            )
        ]

    def _normalize_audit_log(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        raw_data = payload.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        action = data.get("kestrel_action") or _infer_kestrel_action(payload)
        if action is None:
            return []

        user = payload.get("user")
        user_id = payload.get("user_id")
        actor = payload.get("actor")
        actor_id = payload.get("actor_id")
        occurred_at = payload.get("created_at") or payload.get("@timestamp")
        summary = f"GitHub audit: {payload.get('action', action)} ({action})"

        return [
            NormalizedObject(
                kind="event",
                provider_id=raw.provider_id,
                attributes={
                    "action": action,
                    "action_category": _ACTION_CATEGORIES.get(action, "other"),
                    # Never synthesize @users.noreply.github.com addresses. They
                    # are not real mailboxes, they match no identity in any other
                    # connector, and inventing them here contradicts the identity
                    # path above, which deliberately leaves email null.
                    # Correlation runs on provider ids; logins stay in attributes.
                    "actor_email": None,
                    "actor_provider_id": str(actor_id) if actor_id is not None else None,
                    "target_email": None,
                    # Always "identity". GitHub's audit log has no
                    # `identity_type` field -- the heuristic that read one
                    # existed only because a fixture invented it, so on a live
                    # tenant it could never fire.
                    "target_type": "identity",
                    "target_provider_id": str(user_id) if user_id is not None else None,
                    "occurred_at": occurred_at,
                    "summary": summary,
                    "attributes": {
                        "actor_login": actor,
                        "target_login": user,
                        "github_action": payload.get("action"),
                        "permission": data.get("permission"),
                        "scopes": data.get("scopes"),
                        "application_name": data.get("application_name"),
                        "external": data.get("external"),
                        "days_dormant": data.get("days_dormant"),
                        "repo": payload.get("repo"),
                        "visibility": data.get("visibility"),
                        "team": data.get("team"),
                        "hook_id": data.get("hook_id"),
                        "events": data.get("events"),
                    },
                },
                raw_source=payload,
            )
        ]


_PRIVILEGED_PERMISSIONS = frozenset({"admin", "maintain", "owner"})


def _infer_kestrel_action(payload: dict[str, Any]) -> str | None:
    """Normalized action for one audit entry, or None to drop it.

    Order matters. A role change is read from its payload before the name
    lookup, because `org.update_member` covers both promotion and demotion and
    only `data.permission` says which.
    """
    github_action = payload.get("action")
    raw_data = payload.get("data")
    data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
    permission = data.get("permission")

    if github_action == "org.update_member":
        if permission in _PRIVILEGED_PERMISSIONS:
            if data.get("external"):
                return "privilege.external"
            return "privilege.grant"
        # Demotion to plain member is the revocation half, and it is the event
        # an operator most wants when auditing who removed whose access.
        return "privilege.revoke"

    if github_action == _VISIBILITY_ACTION:
        # `repo.access` is emitted for every visibility transition; only the
        # one that exposes a repository outside the org is posture-relevant.
        return "sharing.external" if data.get("visibility") == "public" else None

    if isinstance(github_action, str) and github_action in _GITHUB_ACTION_TO_KESTREL:
        return _GITHUB_ACTION_TO_KESTREL[github_action]

    # Fall back to the payload for actions not in the curated map: an external
    # collaborator or anyone else handed a privileged permission is worth an
    # event whatever GitHub called the action.
    if permission in _PRIVILEGED_PERMISSIONS:
        if data.get("external"):
            return "privilege.external"
        return "privilege.grant"
    return None


def _normalize_actions_permission(raw: RawObject) -> list[NormalizedObject]:
    return settings_from_mapping(raw.payload, _ACTIONS_PERMISSION_SPECS, provider_id_prefix="actions-permission")


def _normalize_runner_group(raw: RawObject) -> list[NormalizedObject]:
    """A runner group's exposure, as one setting per group.

    `allows_public_repositories` is the dangerous one: a self-hosted runner
    reachable from a public repository executes code from any fork's pull
    request on your infrastructure.
    """
    payload = raw.payload
    name = payload.get("name") or raw.provider_id
    return [
        setting_object(
            key=f"actions_runner_group_public_repos:{raw.provider_id}",
            category="security",
            label=f"Runner group '{name}' allows public repositories",
            value=bool(payload.get("allows_public_repositories")),
            value_type="boolean",
            description="Self-hosted runners reachable from public repositories run untrusted code.",
            raw_source=payload,
            provider_id_prefix="runner-group",
        ),
        setting_object(
            key=f"actions_runner_group_visibility:{raw.provider_id}",
            category="access",
            label=f"Runner group '{name}' visibility",
            value=payload.get("visibility"),
            value_type="string",
            description="Which repositories may use this runner group.",
            raw_source=payload,
            provider_id_prefix="runner-group",
        ),
    ]


def _normalize_self_hosted_runner(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    return [
        setting_object(
            key=f"actions_self_hosted_runner:{raw.provider_id}",
            category="security",
            label=f"Self-hosted runner '{payload.get('name') or raw.provider_id}'",
            value={
                "name": payload.get("name"),
                "os": payload.get("os"),
                "status": payload.get("status"),
                "labels": [label.get("name") for label in payload.get("labels") or [] if isinstance(label, dict)],
            },
            value_type="object",
            description="Org-level self-hosted Actions runner.",
            raw_source=payload,
            provider_id_prefix="self-hosted-runner",
        )
    ]


def _normalize_actions_secret(raw: RawObject) -> list[NormalizedObject]:
    """Secret *names* and visibility. GitHub never returns values."""
    payload = raw.payload
    return [
        setting_object(
            key=f"actions_secret_visibility:{raw.provider_id}",
            category="access",
            label=f"Actions secret '{raw.provider_id}' visibility",
            value=payload.get("visibility"),
            value_type="string",
            description="Which repositories can read this org secret.",
            raw_source=payload,
            provider_id_prefix="actions-secret",
        )
    ]


def _normalize_actions_variable(raw: RawObject) -> list[NormalizedObject]:
    """Variable names only -- the collector drops values before this point."""
    payload = raw.payload
    return [
        setting_object(
            key=f"actions_variable_visibility:{raw.provider_id}",
            category="access",
            label=f"Actions variable '{raw.provider_id}' visibility",
            value=payload.get("visibility"),
            value_type="string",
            description="Which repositories can read this org variable.",
            raw_source=payload,
            provider_id_prefix="actions-variable",
        )
    ]


def _normalize_org_webhook(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    config = payload.get("config") or {}
    return [
        setting_object(
            key=f"org_webhook:{raw.provider_id}",
            category="security",
            label=f"Organization webhook to {config.get('url_host') or 'unknown host'}",
            value={
                "host": config.get("url_host"),
                "scheme": config.get("url_scheme"),
                "active": payload.get("active"),
                "events": payload.get("events"),
                # "0" means TLS verification is on; "1" disables it.
                "insecure_ssl": str(config.get("insecure_ssl", "0")) == "1",
            },
            value_type="object",
            description="Org webhooks receive organization events at an external destination.",
            raw_source=payload,
            provider_id_prefix="org-webhook",
        )
    ]


def _normalize_installed_app(raw: RawObject) -> list[NormalizedObject]:
    """An installed GitHub App as an OAuth application plus its permissions.

    GitHub emitted no `oauth_*` objects at all so installed
    Apps -- which hold long-lived org-wide access -- were invisible to every
    OAuth policy and to the `oauth_app_installed` change class.
    """
    payload = raw.payload
    app = payload.get("app_slug") or payload.get("app_id")
    account = payload.get("account") or {}
    name = payload.get("app_slug") or f"app-{app}"
    objects: list[NormalizedObject] = [
        NormalizedObject(
            kind="oauth_application",
            provider_id=raw.provider_id,
            attributes={
                "name": name,
                "publisher": account.get("login") if isinstance(account, dict) else None,
                # GitHub does not expose Marketplace verification here, so this
                # stays unknown rather than being guessed as False.
                "is_verified": None,
            },
            raw_source=payload,
        )
    ]
    permissions = payload.get("permissions") or {}
    if isinstance(permissions, dict):
        for permission, level in sorted(permissions.items()):
            scope_name = f"{permission}:{level}"
            objects.append(
                NormalizedObject(
                    kind="oauth_scope",
                    provider_id=f"{raw.provider_id}:{scope_name}",
                    attributes={
                        "oauth_application_ref": raw.provider_id,
                        "scope_name": scope_name,
                        "is_sensitive": _app_permission_is_sensitive(str(permission), str(level)),
                    },
                    raw_source={"permission": permission, "level": level},
                )
            )
    return objects


def _normalize_credential_authorization(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    login = payload.get("login")
    return [
        setting_object(
            key=f"sso_credential:{raw.provider_id}",
            category="access",
            label=f"SSO-authorized {payload.get('credential_type') or 'credential'} for {login}",
            value={
                "login": login,
                "credential_type": payload.get("credential_type"),
                "scopes": payload.get("scopes"),
                "authorized_at": payload.get("credential_authorized_at"),
                "last_accessed_at": payload.get("credential_accessed_at"),
            },
            value_type="object",
            description="A personal credential authorized to reach org resources through SAML SSO.",
            raw_source=payload,
            provider_id_prefix="sso-credential",
        )
    ]


def _normalize_org_ruleset(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    return [
        setting_object(
            key=f"org_ruleset:{raw.provider_id}",
            category="security",
            label=f"Organization ruleset '{payload.get('name') or raw.provider_id}'",
            value={
                "name": payload.get("name"),
                "enforcement": payload.get("enforcement"),
                "target": payload.get("target"),
            },
            value_type="object",
            description="Org-level branch/tag protection. `disabled` or `evaluate` does not enforce.",
            raw_source=payload,
            provider_id_prefix="org-ruleset",
        )
    ]


def _normalize_security_manager(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    return [
        setting_object(
            key=f"security_manager_team:{raw.provider_id}",
            category="access",
            label=f"Security manager team '{payload.get('name') or payload.get('slug')}'",
            value=payload.get("slug") or payload.get("name"),
            value_type="string",
            description="Teams holding the org-wide security manager role.",
            raw_source=payload,
            provider_id_prefix="security-manager",
        )
    ]


def _normalize_custom_org_role(raw: RawObject) -> list[NormalizedObject]:
    """A custom organization role, privileged when it carries admin permissions."""
    payload = raw.payload
    permissions = payload.get("permissions") or []
    privileged = any(
        isinstance(permission, str) and ("admin" in permission or "manage" in permission) for permission in permissions
    )
    return [
        NormalizedObject(
            kind="role",
            provider_id=f"custom-org-role:{raw.provider_id}",
            attributes={
                "name": payload.get("name") or f"Custom role {raw.provider_id}",
                "is_privileged": privileged,
            },
            raw_source=payload,
        )
    ]


def _normalize_org_invitation(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    inviter = payload.get("inviter") or {}
    return [
        setting_object(
            key=f"pending_invitation:{raw.provider_id}",
            category="access",
            label=f"Pending invitation for {payload.get('login') or payload.get('email')}",
            value={
                "login": payload.get("login"),
                "email": payload.get("email"),
                "role": payload.get("role"),
                "created_at": payload.get("created_at"),
                "inviter": inviter.get("login") if isinstance(inviter, dict) else None,
            },
            value_type="object",
            description="An unaccepted org invitation still grants access once accepted.",
            raw_source=payload,
            provider_id_prefix="org-invitation",
        )
    ]


def _normalize_pat_request(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    owner = payload.get("owner") or {}
    return [
        setting_object(
            key=f"pat_request:{raw.provider_id}",
            category="access",
            label=f"Fine-grained PAT request from {owner.get('login') if isinstance(owner, dict) else 'unknown'}",
            value={
                "owner": owner.get("login") if isinstance(owner, dict) else None,
                "repository_selection": payload.get("repository_selection"),
                "permissions": payload.get("permissions_added") or payload.get("permissions"),
                "created_at": payload.get("created_at"),
            },
            value_type="object",
            description="A pending fine-grained PAT request awaiting an owner's decision.",
            raw_source=payload,
            provider_id_prefix="pat-request",
        )
    ]


def _normalize_org_ip_allow_list(raw: RawObject) -> list[NormalizedObject]:
    """IP allow list enabled flag plus the configured entries.

    `ipAllowListEnabledSetting` is a GraphQL enum: "ENABLED" or "DISABLED".
    We also surface the list of configured entries so a policy can verify
    that the list is non-empty when the feature is enabled.
    """
    payload = raw.payload
    raw_setting = payload.get("enabled_setting")
    enabled: bool | None = None
    if isinstance(raw_setting, str):
        enabled = raw_setting.upper() == "ENABLED"
    entries = [
        {
            "address": e.get("allowListValue"),
            "active": e.get("isActive"),
            "name": e.get("name"),
            "created_at": e.get("createdAt"),
        }
        for e in (payload.get("entries") or [])
        if isinstance(e, dict)
    ]
    return [
        setting_object(
            key="ip_allow_list_enabled",
            category="security",
            label="IP allow list enabled",
            value=enabled,
            value_type="boolean",
            description=(
                "When enabled, only requests from listed IP addresses or CIDR ranges can "
                "access the organization. Requires at least one active entry to be meaningful."
            ),
            raw_source=payload,
            provider_id_prefix="org-security",
        ),
        setting_object(
            key="ip_allow_list_entries",
            category="security",
            label="IP allow list entries",
            value=entries,
            value_type="object",
            description="Active and inactive IP allow list entries for the organization.",
            raw_source=payload,
            provider_id_prefix="org-security",
        ),
    ]


def _normalize_copilot_policy(raw: RawObject) -> list[NormalizedObject]:
    """Org Copilot policy: public-code suggestions and seat management."""
    payload = raw.payload
    return [
        setting_object(
            key="copilot_public_code_suggestions",
            category="security",
            label="Copilot public code suggestions",
            value=payload.get("public_code_suggestions"),
            value_type="string",
            description=(
                "`allow` permits Copilot to suggest code that matches public repositories; "
                "`block` filters those suggestions."
            ),
            raw_source=payload,
            provider_id_prefix="copilot",
        ),
        setting_object(
            key="copilot_seat_management_setting",
            category="access",
            label="Copilot seat management",
            value=payload.get("seat_management_setting"),
            value_type="string",
            description=(
                "`assign_selected` requires explicit assignment; `assign_all` gives every member a seat automatically."
            ),
            raw_source=payload,
            provider_id_prefix="copilot",
        ),
    ]


def _normalize_copilot_seat(raw: RawObject) -> list[NormalizedObject]:
    """One Copilot seat, with last-activity timestamp for staleness detection."""
    payload = raw.payload
    assignee = payload.get("assignee") or {}
    login = assignee.get("login") if isinstance(assignee, dict) else raw.provider_id
    return [
        setting_object(
            key=f"copilot_seat:{login}",
            category="access",
            label=f"Copilot seat for {login}",
            value={
                "login": login,
                "last_activity_at": payload.get("last_activity_at"),
                "last_activity_editor": payload.get("last_activity_editor"),
                "created_at": payload.get("created_at"),
                "pending_cancellation_date": payload.get("pending_cancellation_date"),
            },
            value_type="object",
            description="Copilot seat assignment. `last_activity_at` null means the seat has never been used.",
            raw_source=payload,
            provider_id_prefix="copilot-seat",
        )
    ]


def _normalize_approved_pat(raw: RawObject) -> list[NormalizedObject]:
    """An approved fine-grained PAT, with its permission set and scope."""
    payload = raw.payload
    owner = payload.get("owner") or {}
    permissions = payload.get("permissions") or {}
    # Flatten the nested permission map (org/repo/user scope -> {name -> level})
    # into a flat list for easier policy consumption.
    flat_permissions: list[dict[str, str]] = []
    for scope_group, perms in permissions.items() if isinstance(permissions, dict) else []:
        if isinstance(perms, dict):
            for perm_name, level in perms.items():
                flat_permissions.append({"scope": scope_group, "name": perm_name, "level": str(level)})
    return [
        setting_object(
            key=f"approved_pat:{raw.provider_id}",
            category="access",
            label=f"Approved PAT from {owner.get('login') if isinstance(owner, dict) else 'unknown'}",
            value={
                "owner": owner.get("login") if isinstance(owner, dict) else None,
                "repository_selection": payload.get("repository_selection"),
                "permissions": flat_permissions,
                "access_granted_at": payload.get("access_granted_at"),
                "token_expires_at": payload.get("token_expires_at"),
                "token_last_used_at": payload.get("token_last_used_at"),
                "token_expired": payload.get("token_expired"),
            },
            value_type="object",
            description="A fine-grained PAT granted access to org resources. Token value is never returned by GitHub.",
            raw_source=payload,
            provider_id_prefix="approved-pat",
        )
    ]


def _normalize_org_package(raw: RawObject) -> list[NormalizedObject]:
    """An org package, with its visibility and linked repository."""
    payload = raw.payload
    name = str(payload.get("name") or raw.provider_id)
    pkg_type = str(payload.get("package_type") or "unknown")
    visibility = str(payload.get("visibility") or "private")
    repo = payload.get("repository") or {}
    repo_name = repo.get("name") if isinstance(repo, dict) else None
    repo_private = repo.get("private") if isinstance(repo, dict) else None
    return [
        setting_object(
            key=f"org_package:{pkg_type}:{name}",
            category="sharing" if visibility == "public" else "access",
            label=f"Package '{name}' ({pkg_type}, {visibility})",
            value={
                "name": name,
                "package_type": pkg_type,
                "visibility": visibility,
                "repository_name": repo_name,
                "repository_private": repo_private,
            },
            value_type="object",
            description=(
                "A public package from a private repository exposes the package's "
                "contents beyond what the repository's visibility would allow."
            ),
            raw_source=payload,
            provider_id_prefix="org-package",
        )
    ]


_ORG_SURFACE_NORMALIZERS: dict[str, Callable[[RawObject], list[NormalizedObject]]] = {
    "actions_permission": _normalize_actions_permission,
    "runner_group": _normalize_runner_group,
    "self_hosted_runner": _normalize_self_hosted_runner,
    "actions_secret": _normalize_actions_secret,
    "actions_variable": _normalize_actions_variable,
    "org_webhook": _normalize_org_webhook,
    "installed_app": _normalize_installed_app,
    "credential_authorization": _normalize_credential_authorization,
    "org_ruleset": _normalize_org_ruleset,
    "security_manager": _normalize_security_manager,
    "custom_org_role": _normalize_custom_org_role,
    "org_invitation": _normalize_org_invitation,
    "pat_request": _normalize_pat_request,
    # Extended coverage
    "org_ip_allow_list": _normalize_org_ip_allow_list,
    "copilot_policy": _normalize_copilot_policy,
    "copilot_seat": _normalize_copilot_seat,
    "approved_pat": _normalize_approved_pat,
    "org_package": _normalize_org_package,
}


# -- per-repository posture ----------------------------------------
#
# Every setting here is scoped to the repository it governs rather than emitted
# at the tenant with the repo name buried in its key. It carries
# `subject_type` / `subject_ref` for the upsert, and an `applies_to`
# relationship so the same link exists in the graph.


def _repo_setting(
    repo: dict[str, Any],
    *,
    key: str,
    category: str,
    label: str,
    value: Any,
    value_type: str,
    description: str | None,
    raw_source: dict[str, Any],
) -> NormalizedObject:
    repo_ref = str(repo.get("id") or "")
    obj = setting_object(
        key=key,
        category=category,
        label=label,
        value=value,
        value_type=value_type,
        description=description,
        raw_source=raw_source,
        provider_id_prefix=f"repo-setting:{repo_ref}",
    )
    obj.attributes["subject_type"] = "resource"
    obj.attributes["subject_ref"] = repo_ref
    obj.relationships = [
        NormalizedRelationship(
            edge_type="applies_to",
            source_ref=obj.provider_id,
            target_ref=repo_ref,
        )
    ]
    return obj


def _normalize_repo_security_analysis(raw: RawObject) -> list[NormalizedObject]:
    """GHAS, secret scanning, push protection, and Dependabot enablement.

    GitHub reports each as `{"status": "enabled"|"disabled"}`; a feature absent
    from the block is not available on the plan at all, which is different from
    being switched off and is left uncollected rather than reported as off.
    """
    payload = raw.payload
    repo = payload.get("repo") or {}
    analysis = payload.get("security_and_analysis") or {}
    specs = [
        ("advanced_security", "GitHub Advanced Security"),
        ("secret_scanning", "Secret scanning"),
        ("secret_scanning_push_protection", "Secret scanning push protection"),
        ("secret_scanning_validity_checks", "Secret scanning validity checks"),
        ("dependabot_security_updates", "Dependabot security updates"),
    ]
    out: list[NormalizedObject] = []
    for field, label in specs:
        entry = analysis.get(field)
        if not isinstance(entry, dict) or "status" not in entry:
            continue
        out.append(
            _repo_setting(
                repo,
                key=f"repo_{field}_enabled",
                category="security",
                label=f"{label} on {repo.get('name')}",
                value=entry.get("status") == "enabled",
                value_type="boolean",
                description=f"{label} enablement for this repository.",
                raw_source=payload,
            )
        )
    return out


def _normalize_repo_branch_protection(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    repo = payload.get("repo") or {}
    protection = payload.get("protection") or {}
    protected = bool(payload.get("protected"))

    def _enabled(section: str) -> bool:
        entry = protection.get(section)
        if isinstance(entry, dict):
            return bool(entry.get("enabled", True))
        return bool(entry)

    reviews = protection.get("required_pull_request_reviews")
    review_count = reviews.get("required_approving_review_count") if isinstance(reviews, dict) else None
    return [
        _repo_setting(
            repo,
            key="repo_default_branch_protected",
            category="security",
            label=f"Default branch protection on {repo.get('name')}",
            value=protected,
            value_type="boolean",
            description=(
                f"Whether {payload.get('branch')} is a protected branch. "
                "An unprotected default branch accepts direct pushes."
            ),
            raw_source=payload,
        ),
        _repo_setting(
            repo,
            key="repo_branch_protection_detail",
            category="security",
            label=f"Default branch protection detail on {repo.get('name')}",
            value={
                "branch": payload.get("branch"),
                "protected": protected,
                "required_reviews": review_count,
                "dismiss_stale_reviews": (reviews.get("dismiss_stale_reviews") if isinstance(reviews, dict) else None),
                "require_code_owner_reviews": (
                    reviews.get("require_code_owner_reviews") if isinstance(reviews, dict) else None
                ),
                "enforce_admins": _enabled("enforce_admins"),
                "required_status_checks": _enabled("required_status_checks"),
                "required_signatures": _enabled("required_signatures"),
                "allow_force_pushes": _enabled("allow_force_pushes"),
                "allow_deletions": _enabled("allow_deletions"),
                "required_linear_history": _enabled("required_linear_history"),
            },
            value_type="object",
            description="Branch protection settings on the repository's default branch.",
            raw_source=payload,
        ),
    ]


def _normalize_repo_ruleset(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    repo = payload.get("repo") or {}
    ruleset = payload.get("ruleset") or {}
    return [
        _repo_setting(
            repo,
            key=f"repo_ruleset:{ruleset.get('id')}",
            category="security",
            label=f"Ruleset '{ruleset.get('name')}' on {repo.get('name')}",
            value={
                "name": ruleset.get("name"),
                "enforcement": ruleset.get("enforcement"),
                "target": ruleset.get("target"),
            },
            value_type="object",
            description="Repository ruleset. `disabled` or `evaluate` enforces nothing.",
            raw_source=payload,
        )
    ]


def _normalize_repo_webhook(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    repo = payload.get("repo") or {}
    hook = payload.get("hook") or {}
    config = hook.get("config") or {}
    return [
        _repo_setting(
            repo,
            key=f"repo_webhook:{hook.get('id')}",
            category="security",
            label=f"Webhook on {repo.get('name')} to {config.get('url_host') or 'unknown host'}",
            value={
                "host": config.get("url_host"),
                "scheme": config.get("url_scheme"),
                "active": hook.get("active"),
                "events": hook.get("events"),
                "insecure_ssl": str(config.get("insecure_ssl", "0")) == "1",
            },
            value_type="object",
            description="Repository webhook delivering events to an external destination.",
            raw_source=payload,
        )
    ]


def _normalize_deploy_key(raw: RawObject) -> list[NormalizedObject]:
    """A deploy key grants repository access outside the member and team model."""
    payload = raw.payload
    repo = payload.get("repo") or {}
    key = payload.get("key") or {}
    return [
        _repo_setting(
            repo,
            key=f"repo_deploy_key:{key.get('id')}",
            category="access",
            label=f"Deploy key '{key.get('title')}' on {repo.get('name')}",
            value={
                "title": key.get("title"),
                # A writable deploy key is a push credential that outlives
                # whoever added it.
                "read_only": key.get("read_only"),
                "created_at": key.get("created_at"),
                "last_used": key.get("last_used"),
            },
            value_type="object",
            description="Deploy keys bypass the member and team access model.",
            raw_source=payload,
        )
    ]


def _normalize_repo_environment(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    repo = payload.get("repo") or {}
    environment = payload.get("environment") or {}
    rules = environment.get("protection_rules") or []
    rule_types = [r.get("type") for r in rules if isinstance(r, dict)]
    return [
        _repo_setting(
            repo,
            key=f"repo_environment:{environment.get('name')}",
            category="security",
            label=f"Environment '{environment.get('name')}' on {repo.get('name')}",
            value={
                "name": environment.get("name"),
                "protection_rules": rule_types,
                "has_reviewers": "required_reviewers" in rule_types,
            },
            value_type="object",
            description=(
                "Deployment environments hold secrets; one without required "
                "reviewers deploys on any qualifying workflow run."
            ),
            raw_source=payload,
        )
    ]


def _normalize_repo_actions_permission(raw: RawObject) -> list[NormalizedObject]:
    payload = raw.payload
    repo = payload.get("repo") or {}
    permissions = payload.get("permissions") or {}
    return [
        _repo_setting(
            repo,
            key="repo_actions_permissions",
            category="security",
            label=f"Actions policy on {repo.get('name')}",
            value={
                "enabled": permissions.get("enabled"),
                "allowed_actions": permissions.get("allowed_actions"),
            },
            value_type="object",
            description="Which Actions this repository may run.",
            raw_source=payload,
        )
    ]


def _normalize_secret_scanning_alert(raw: RawObject) -> list[NormalizedObject]:
    """The number of open alerts, never their contents."""
    payload = raw.payload
    repo = payload.get("repo") or {}
    return [
        _repo_setting(
            repo,
            key="repo_open_secret_scanning_alerts",
            category="security",
            label=f"Open secret-scanning alerts on {repo.get('name')}",
            value=int(payload.get("open_alert_count") or 0),
            value_type="number",
            description=("Count of unresolved secret-scanning alerts. Kestrel never collects the detected secret itself."),
            raw_source=payload,
        )
    ]


def _normalize_dependabot_alert(raw: RawObject) -> list[NormalizedObject]:
    """Count of open Dependabot alerts. Advisory details are never stored."""
    payload = raw.payload
    repo = payload.get("repo") or {}
    return [
        _repo_setting(
            repo,
            key="repo_open_dependabot_alerts",
            category="security",
            label=f"Open Dependabot alerts on {repo.get('name')}",
            value=int(payload.get("open_alert_count") or 0),
            value_type="number",
            description=(
                "Count of open Dependabot vulnerability alerts. "
                "Advisory details (CVE, CVSS, affected package) are not stored."
            ),
            raw_source=payload,
        )
    ]


def _normalize_code_scanning_alert(raw: RawObject) -> list[NormalizedObject]:
    """Count of open code-scanning alerts. Rule details are never stored."""
    payload = raw.payload
    repo = payload.get("repo") or {}
    return [
        _repo_setting(
            repo,
            key="repo_open_code_scanning_alerts",
            category="security",
            label=f"Open code-scanning alerts on {repo.get('name')}",
            value=int(payload.get("open_alert_count") or 0),
            value_type="number",
            description=(
                "Count of open code-scanning alerts. Rule identifiers, affected code, and alert bodies are not stored."
            ),
            raw_source=payload,
        )
    ]


def _normalize_repo_vulnerability_alerts(raw: RawObject) -> list[NormalizedObject]:
    """Whether Dependabot vulnerability alerts are enabled on a repository."""
    payload = raw.payload
    repo = payload.get("repo") or {}
    return [
        _repo_setting(
            repo,
            key="repo_vulnerability_alerts_enabled",
            category="security",
            label=f"Vulnerability alerts on {repo.get('name')}",
            value=bool(payload.get("enabled")),
            value_type="boolean",
            description=(
                "Dependabot vulnerability alerts notify when a dependency with a known "
                "vulnerability is found. Disabling them leaves the repository unmonitored."
            ),
            raw_source=payload,
        )
    ]


def _normalize_repo_code_scanning(raw: RawObject) -> list[NormalizedObject]:
    """Code-scanning default-setup state for a repository."""
    payload = raw.payload
    repo = payload.get("repo") or {}
    state = str(payload.get("state") or "not-configured")
    return [
        _repo_setting(
            repo,
            key="repo_code_scanning_setup",
            category="security",
            label=f"Code scanning setup on {repo.get('name')}",
            value={
                "state": state,
                "languages": payload.get("languages"),
                "query_suite": payload.get("query_suite"),
            },
            value_type="object",
            description=(
                "`configured` means code scanning is active via default setup. "
                "`not-configured` means GHAS is enabled but code scanning is not set up. "
                "Absence means GHAS is not available on the plan."
            ),
            raw_source=payload,
        )
    ]


_REPO_POSTURE_NORMALIZERS: dict[str, Callable[[RawObject], list[NormalizedObject]]] = {
    "repo_security_analysis": _normalize_repo_security_analysis,
    "repo_branch_protection": _normalize_repo_branch_protection,
    "repo_ruleset": _normalize_repo_ruleset,
    "repo_webhook": _normalize_repo_webhook,
    "deploy_key": _normalize_deploy_key,
    "repo_environment": _normalize_repo_environment,
    "repo_actions_permission": _normalize_repo_actions_permission,
    "secret_scanning_alert": _normalize_secret_scanning_alert,
    # Extended coverage
    "dependabot_alert": _normalize_dependabot_alert,
    "code_scanning_alert": _normalize_code_scanning_alert,
    "repo_vulnerability_alerts": _normalize_repo_vulnerability_alerts,
    "repo_code_scanning": _normalize_repo_code_scanning,
}

# One dispatch for both module-level families.
_MODULE_NORMALIZERS: dict[str, Callable[[RawObject], list[NormalizedObject]]] = {
    **_ORG_SURFACE_NORMALIZERS,
    **_REPO_POSTURE_NORMALIZERS,
}
