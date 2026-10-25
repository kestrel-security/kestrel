# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector-aware catalogs and deterministic intent templates for policy AI generate."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

# Classic Okta admin role display names — must match collector ADMIN_ROLES and the okta-posture pack.
OKTA_PRIVILEGED_ROLES: tuple[str, ...] = (
    "Super Administrator",
    "Organization Administrator",
    "Application Administrator",
    "Help Desk Administrator",
    "Group Administrator",
)

OKTA_TENANT_SETTING_KEYS: tuple[str, ...] = (
    "mfa_enroll_policy_required",
    "subdomain",
    "password_min_length",
    "password_complexity",
    "threat_insight_enabled",
    "okta_app_sign_on_mode",
)

OKTA_EVENT_ACTIONS: tuple[str, ...] = (
    "privilege.grant",
    "privilege.revoke",
    "mfa.disable",
    "threat.detected",
    "admin.console",
    "identity.deactivate",
    "api.token.create",
)

_CONNECTOR_ALIASES: dict[str, str] = {
    "okta": "okta",
    "idp": "okta",
}


def normalize_connector_hint(hint: str | None) -> str | None:
    if not hint:
        return None
    key = hint.strip().lower().replace(" ", "_").replace("-", "_")
    return _CONNECTOR_ALIASES.get(key, key)


def _slug_from_intent(intent: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", intent.lower().strip())[:48].strip("-")
    if not cleaned:
        cleaned = "custom-draft"
    digest = hashlib.sha256(intent.encode("utf-8")).hexdigest()[:8]
    return f"{cleaned}-{digest}"[:64].strip("-")


@dataclass(frozen=True)
class IntentTemplate:
    name: str
    resource_type: str
    connector: str | None
    pattern: re.Pattern[str]
    source_factory: Any  # callable(intent) -> str
    fixtures: dict[str, Any]


def _okta_admin_without_mfa_source(intent: str) -> str:
    policy_id = _slug_from_intent(intent)
    roles_repr = repr(OKTA_PRIVILEGED_ROLES)
    return f'''POLICY_ID = "{policy_id}"
TITLE = "Detect Okta privileged administrators without MFA"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = {intent.strip()[:500]!r}
REMEDIATION = "Require MFA for the privileged Okta admin, or remove the admin role assignment."
COMPLIANCE = {{"custom": ["OKTA-02"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}}

OKTA_PRIVILEGED_ROLES = {roles_repr}

def policy(resource):
    application = resource.get("application") or {{}}
    identity = resource.get("identity") or {{}}
    roles = resource.get("roles") or []
    if application.get("type") != "okta":
        return True
    if not any(r in roles for r in OKTA_PRIVILEGED_ROLES):
        return True
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {{}}
    application = resource.get("application") or {{}}
    return {{
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.mfa_enabled": identity.get("mfa_enabled"),
        "application.name": application.get("name"),
    }}
'''


def _okta_mfa_enroll_not_required_source(intent: str) -> str:
    policy_id = _slug_from_intent(intent)
    return f'''POLICY_ID = "{policy_id}"
TITLE = "Detect Okta orgs that do not require multifactor enrollment"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = {intent.strip()[:500]!r}
REMEDIATION = "Require MFA enrollment in Okta Security → Authenticators / multifactor policies."
COMPLIANCE = {{"custom": ["OKTA-01"], "soc2": ["CC6.1", "CC6.2"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}}

def policy(resource):
    application = resource.get("application") or {{}}
    setting = resource.get("setting") or {{}}
    if application.get("type") != "okta":
        return True
    if setting.get("key") != "mfa_enroll_policy_required":
        return True
    return setting.get("value") != False


def evidence(resource):
    setting = resource.get("setting") or {{}}
    application = resource.get("application") or {{}}
    return {{
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "setting.label": setting.get("label"),
        "application.name": application.get("name"),
    }}
'''


def _okta_disabled_privileged_admin_source(intent: str) -> str:
    policy_id = _slug_from_intent(intent)
    roles_repr = repr(OKTA_PRIVILEGED_ROLES)
    return f'''POLICY_ID = "{policy_id}"
TITLE = "Detect disabled Okta users that still hold privileged admin roles"
SEVERITY = "critical"
RESOURCE_TYPE = "identity"
DESCRIPTION = {intent.strip()[:500]!r}
REMEDIATION = "Remove privileged admin roles from suspended or deprovisioned Okta accounts immediately."
COMPLIANCE = {{"custom": ["OKTA-02"], "soc2": ["CC6.3"], "cis": ["6.8"], "nist_csf": ["PR.AC-1"]}}

OKTA_PRIVILEGED_ROLES = {roles_repr}

def policy(resource):
    application = resource.get("application") or {{}}
    identity = resource.get("identity") or {{}}
    roles = resource.get("roles") or []
    if application.get("type") != "okta":
        return True
    if not any(r in roles for r in OKTA_PRIVILEGED_ROLES):
        return True
    return not identity.get("is_disabled")


def evidence(resource):
    identity = resource.get("identity") or {{}}
    application = resource.get("application") or {{}}
    return {{
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.is_disabled": identity.get("is_disabled"),
        "application.name": application.get("name"),
    }}
'''


def _okta_dormant_admin_source(intent: str) -> str:
    policy_id = _slug_from_intent(intent)
    roles_repr = repr(OKTA_PRIVILEGED_ROLES)
    return f'''POLICY_ID = "{policy_id}"
TITLE = "Detect privileged Okta admins inactive for 90+ days"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = {intent.strip()[:500]!r}
REMEDIATION = "Review the dormant admin account, remove unnecessary privileges, or confirm continued need."
COMPLIANCE = {{"custom": ["OKTA-02"], "soc2": ["CC6.1"], "cis": ["6.3"], "nist_csf": ["PR.AC-7"]}}

OKTA_PRIVILEGED_ROLES = {roles_repr}
DORMANT_DAYS = 90


def active_within_days(last_active, days):
    if last_active is None:
        return False
    try:
        ts = last_active.timestamp()
    except Exception:
        return False
    return (time.time() - ts) <= days * 86400


def policy(resource):
    application = resource.get("application") or {{}}
    identity = resource.get("identity") or {{}}
    roles = resource.get("roles") or []
    if application.get("type") != "okta":
        return True
    if not any(r in roles for r in OKTA_PRIVILEGED_ROLES):
        return True
    return active_within_days(identity.get("last_active_at"), DORMANT_DAYS)


def evidence(resource):
    identity = resource.get("identity") or {{}}
    application = resource.get("application") or {{}}
    return {{
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
        "identity.last_active_at": identity.get("last_active_at"),
        "application.name": application.get("name"),
    }}
'''


def _okta_password_policy_weak_source(intent: str) -> str:
    policy_id = _slug_from_intent(intent)
    return f'''POLICY_ID = "{policy_id}"
TITLE = "Detect weak Okta password policy (minimum length below 12)"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = {intent.strip()[:500]!r}
REMEDIATION = "Increase the Okta password policy minimum length to at least 12 and enable complexity requirements."
COMPLIANCE = {{"custom": ["OKTA-01"], "soc2": ["CC6.1"], "cis": ["5.2"], "nist_csf": ["PR.AC-1"]}}

MIN_PASSWORD_LENGTH = 12

def policy(resource):
    application = resource.get("application") or {{}}
    setting = resource.get("setting") or {{}}
    if application.get("type") != "okta":
        return True
    if setting.get("key") != "password_min_length":
        return True
    value = setting.get("value")
    if value is None:
        return True
    try:
        length = int(value)
    except (TypeError, ValueError):
        return True
    return length >= MIN_PASSWORD_LENGTH


def evidence(resource):
    setting = resource.get("setting") or {{}}
    application = resource.get("application") or {{}}
    return {{
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }}
'''


def _okta_app_bookmark_or_swa_source(intent: str) -> str:
    policy_id = _slug_from_intent(intent)
    return f'''POLICY_ID = "{policy_id}"
TITLE = "Detect Okta apps using bookmark or SWA sign-on (no SSO)"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = {intent.strip()[:500]!r}
REMEDIATION = "Migrate the application to SAML or OIDC SSO, or document an approved exception for bookmark/SWA access."
COMPLIANCE = {{"custom": ["OKTA-03"], "soc2": ["CC6.1"], "cis": ["6.7"], "nist_csf": ["PR.AC-3"]}}

WEAK_SIGN_ON_MODES = ("BOOKMARK", "BROWSER_PLUGIN")

def policy(resource):
    application = resource.get("application") or {{}}
    setting = resource.get("setting") or {{}}
    if application.get("type") != "okta":
        return True
    key = str(setting.get("key") or "")
    if not key.startswith("okta_app_sign_on_mode:"):
        return True
    value = setting.get("value") or {{}}
    mode = str(value.get("sign_on_mode") or "").upper()
    if mode not in WEAK_SIGN_ON_MODES:
        return True
    return False


def evidence(resource):
    setting = resource.get("setting") or {{}}
    application = resource.get("application") or {{}}
    return {{
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }}
'''


OKTA_IDENTITY_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "grace-id",
            "identity": {
                "email": "grace@acme.example.com",
                "display_name": "Grace Hopper",
                "mfa_enabled": False,
                "is_disabled": False,
                "last_active_at": {"$days_ago": 120},
            },
            "application": {"type": "okta", "name": "Okta"},
            "roles": ["Application Administrator"],
        },
        {
            "_subject_id": "ada-id",
            "identity": {
                "email": "ada@acme.example.com",
                "display_name": "Ada Lovelace",
                "mfa_enabled": True,
                "is_disabled": False,
                "last_active_at": {"$days_ago": 5},
            },
            "application": {"type": "okta", "name": "Okta"},
            "roles": ["Super Administrator"],
        },
    ],
    "expected_match_subject_ids": ["grace-id"],
}

OKTA_DISABLED_ADMIN_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "former-id",
            "identity": {
                "email": "former@acme.example.com",
                "display_name": "Former Employee",
                "is_disabled": True,
                "mfa_enabled": False,
            },
            "application": {"type": "okta", "name": "Okta"},
            "roles": ["Super Administrator"],
        },
        {
            "_subject_id": "ada-id",
            "identity": {
                "email": "ada@acme.example.com",
                "display_name": "Ada Lovelace",
                "is_disabled": False,
                "mfa_enabled": True,
            },
            "application": {"type": "okta", "name": "Okta"},
            "roles": ["Super Administrator"],
        },
    ],
    "expected_match_subject_ids": ["former-id"],
}

OKTA_DORMANT_ADMIN_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "grace-id",
            "identity": {
                "email": "grace@acme.example.com",
                "display_name": "Grace Hopper",
                "last_active_at": {"$days_ago": 120},
                "mfa_enabled": False,
            },
            "application": {"type": "okta", "name": "Okta"},
            "roles": ["Application Administrator"],
        },
        {
            "_subject_id": "ada-id",
            "identity": {
                "email": "ada@acme.example.com",
                "display_name": "Ada Lovelace",
                "last_active_at": {"$days_ago": 5},
                "mfa_enabled": True,
            },
            "application": {"type": "okta", "name": "Okta"},
            "roles": ["Super Administrator"],
        },
    ],
    "expected_match_subject_ids": ["grace-id"],
}

OKTA_PASSWORD_POLICY_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "weak-password",
            "setting": {
                "key": "password_min_length",
                "value": 8,
                "value_type": "number",
                "category": "security",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
        {
            "_subject_id": "strong-password",
            "setting": {
                "key": "password_min_length",
                "value": 14,
                "value_type": "number",
                "category": "security",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
    ],
    "expected_match_subject_ids": ["weak-password"],
}

OKTA_BOOKMARK_SWA_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "bookmark-app",
            "setting": {
                "key": "okta_app_sign_on_mode:0oabookmark000000004",
                "value": {
                    "app_id": "0oabookmark000000004",
                    "name": "Legacy HR Portal",
                    "sign_on_mode": "BOOKMARK",
                },
                "value_type": "object",
                "category": "access",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
        {
            "_subject_id": "saml-app",
            "setting": {
                "key": "okta_app_sign_on_mode:0oainternal000000003",
                "value": {
                    "app_id": "0oainternal000000003",
                    "name": "Internal HR",
                    "sign_on_mode": "SAML_2_0",
                },
                "value_type": "object",
                "category": "access",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
    ],
    "expected_match_subject_ids": ["bookmark-app"],
}

OKTA_TENANT_SETTING_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "setting-mfa-off",
            "setting": {
                "key": "mfa_enroll_policy_required",
                "value": False,
                "value_bool": False,
                "category": "security",
                "label": "MFA enrollment policy requires a factor",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
        {
            "_subject_id": "setting-mfa-on",
            "setting": {
                "key": "mfa_enroll_policy_required",
                "value": True,
                "value_bool": True,
                "category": "security",
                "label": "MFA enrollment policy requires a factor",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
    ],
    "expected_match_subject_ids": ["setting-mfa-off"],
}

OKTA_EVENT_FIXTURES: dict[str, Any] = {
    "rows": [
        {
            "_subject_id": "evt-mfa-off",
            "event": {
                "action": "mfa.disable",
                "action_category": "mfa",
                "actor_email": "grace@acme.example.com",
                "target_email": "grace@acme.example.com",
                "occurred_at": "2026-07-29T12:00:00+00:00",
                "summary": "MFA factor deactivated",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
        {
            "_subject_id": "evt-login",
            "event": {
                "action": "admin.console",
                "actor_email": "ada@acme.example.com",
                "occurred_at": "2026-07-29T12:00:00+00:00",
                "summary": "Admin console access",
            },
            "application": {"type": "okta", "name": "Okta"},
        },
    ],
    "expected_match_subject_ids": ["evt-mfa-off"],
}

INTENT_TEMPLATES: tuple[IntentTemplate, ...] = (
    IntentTemplate(
        name="okta-admin-without-mfa",
        resource_type="identity",
        connector="okta",
        pattern=re.compile(
            r"(okta.*(admin|administrator).*(without|no|missing|lack).*mfa"
            r"|(admin|administrator).*(without|no|missing|lack).*mfa.*okta"
            r"|detect.*okta.*admin.*mfa)",
            re.IGNORECASE,
        ),
        source_factory=_okta_admin_without_mfa_source,
        fixtures=OKTA_IDENTITY_FIXTURES,
    ),
    IntentTemplate(
        name="okta-mfa-enroll-not-required",
        resource_type="tenant_setting",
        connector="okta",
        pattern=re.compile(
            r"(okta.*(mfa|multifactor).*(not required|enroll.*not|without enforce)"
            r"|(mfa|multifactor).*(not required|enroll.*not).*okta"
            r"|org.*mfa.*not.*required.*okta)",
            re.IGNORECASE,
        ),
        source_factory=_okta_mfa_enroll_not_required_source,
        fixtures=OKTA_TENANT_SETTING_FIXTURES,
    ),
    IntentTemplate(
        name="okta-disabled-privileged-admin",
        resource_type="identity",
        connector="okta",
        pattern=re.compile(
            r"(okta.*(disabled|suspended|deprovisioned).*(admin|privileged)"
            r"|(disabled|suspended).*okta.*(admin|privileged)"
            r"|(disabled|suspended).*(admin|privileged).*okta)",
            re.IGNORECASE,
        ),
        source_factory=_okta_disabled_privileged_admin_source,
        fixtures=OKTA_DISABLED_ADMIN_FIXTURES,
    ),
    IntentTemplate(
        name="okta-dormant-admin",
        resource_type="identity",
        connector="okta",
        pattern=re.compile(
            r"(dormant.*okta|okta.*(dormant|inactive.*(admin|privileged))"
            r"|(inactive|90).*(admin|privileged).*okta"
            r"|okta.*(admin|administrator|privileged).*(not|never|no|without|haven't|hasn't)"
            r".*(sign|log|login|active|activity)"
            r"|okta.*(admin|administrator|privileged).*\d+\s*days)",
            re.IGNORECASE,
        ),
        source_factory=_okta_dormant_admin_source,
        fixtures=OKTA_DORMANT_ADMIN_FIXTURES,
    ),
    IntentTemplate(
        name="okta-password-policy-weak",
        resource_type="tenant_setting",
        connector="okta",
        pattern=re.compile(
            r"(weak.*okta.*password|okta.*password.*(weak|min)"
            r"|password.*policy.*okta)",
            re.IGNORECASE,
        ),
        source_factory=_okta_password_policy_weak_source,
        fixtures=OKTA_PASSWORD_POLICY_FIXTURES,
    ),
    IntentTemplate(
        name="okta-app-bookmark-or-swa",
        resource_type="tenant_setting",
        connector="okta",
        pattern=re.compile(
            r"(okta.*(bookmark|swa|browser.?plugin)|(bookmark|swa).*okta)",
            re.IGNORECASE,
        ),
        source_factory=_okta_app_bookmark_or_swa_source,
        fixtures=OKTA_BOOKMARK_SWA_FIXTURES,
    ),
)


def match_intent_template(
    intent: str,
    *,
    connector_hint: str | None = None,
    resource_type: str | None = None,
) -> IntentTemplate | None:
    """Return a high-confidence template for known posture intents, else None."""
    connector = normalize_connector_hint(connector_hint)
    for template in INTENT_TEMPLATES:
        if resource_type and template.resource_type != resource_type:
            continue
        if template.connector and connector and template.connector != connector:
            continue
        if template.pattern.search(intent):
            return template
    # Okta admin-without-MFA is common enough to match without explicit connector hint.
    if connector in (None, "okta"):
        for template in INTENT_TEMPLATES:
            if (
                template.name == "okta-admin-without-mfa"
                and template.pattern.search(intent)
                and (resource_type is None or template.resource_type == resource_type)
            ):
                return template
    return None


def few_shot_for_connector(connector: str | None, resource_type: str | None) -> str:
    """Return a short example policy for the LLM prompt."""
    connector = normalize_connector_hint(connector)
    if connector != "okta":
        return ""
    if resource_type == "tenant_setting":
        return _okta_mfa_enroll_not_required_source("Example: Okta MFA enroll not required")
    if resource_type == "event":
        return """POLICY_ID = "okta-activity-mfa-disabled"
TITLE = "Detect Okta MFA factor deactivation events"
SEVERITY = "high"
RESOURCE_TYPE = "event"
DESCRIPTION = "Alert when MFA is disabled on an Okta account."
REMEDIATION = "Investigate and re-enable MFA."

def policy(resource):
    application = resource.get("application") or {}
    event = resource.get("event") or {}
    if application.get("type") != "okta":
        return True
    return event.get("action") != "mfa.disable"

def evidence(resource):
    event = resource.get("event") or {}
    return {"event.action": event.get("action"), "event.summary": event.get("summary")}
"""
    return _okta_admin_without_mfa_source("Example: Okta admins without MFA")


def connector_catalog_for_prompt(connector: str | None, resource_type: str | None = None) -> str:
    """Extra context injected into LLM prompts for a connected app."""
    connector = normalize_connector_hint(connector)
    if connector != "okta":
        return ""

    lines = [
        'Okta connector catalog (application.type == "okta"):',
        f"- Privileged admin role names (resource.roles[]): {', '.join(repr(r) for r in OKTA_PRIVILEGED_ROLES)}",
        f"- tenant_setting keys: {', '.join(OKTA_TENANT_SETTING_KEYS)}",
        f"- event.action values: {', '.join(OKTA_EVENT_ACTIONS)}",
        "- identity fields: email, display_name, mfa_enabled, is_disabled, is_external, last_active_at",
        "- Return True if compliant; False opens a finding.",
    ]
    example = few_shot_for_connector("okta", resource_type)
    if example:
        lines.append("\nExample policy for this connector:\n" + example)
    return "\n".join(lines)
