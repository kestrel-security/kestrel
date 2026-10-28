# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector-aware catalogs and deterministic intent templates for policy AI generate."""

from __future__ import annotations

import ast
import functools
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kestrel.policies.cross_app_fixtures import CROSS_APP_FIXTURE_SETS
from kestrel.policies.generate_intent import (
    CROSS_APP_CONNECTOR,
    SCOPE_CROSS_APP,
    normalize_connector_hint,
    resolve_scope,
)
from kestrel.policies.packs import get_packs_dir

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

#: application.type -> the pack whose reviewed policies describe that connector's surface.
CONNECTOR_PACKS: dict[str, str] = {
    "okta": "okta-posture",
    "github": "github-posture",
    "google_workspace": "gws-posture",
    "slack": "slack-posture",
    CROSS_APP_CONNECTOR: "cross-app",
}


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
TITLE = "Okta privileged administrators without MFA"
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
TITLE = "Okta orgs that do not require multifactor enrollment"
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
TITLE = "Disabled Okta users that still hold privileged admin roles"
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
TITLE = "Privileged Okta admins inactive for 90+ days"
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
TITLE = "Weak Okta password policy (minimum length below 12)"
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
TITLE = "Okta apps using bookmark or SWA sign-on (no SSO)"
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


def _okta_user(
    subject_id: str, email: str, *, is_external: bool, days_ago: int | None, disabled: bool = False
) -> dict[str, Any]:
    return {
        "_subject_id": subject_id,
        "identity": {
            "email": email,
            "display_name": subject_id.removesuffix("-id").replace("-", " ").title(),
            "is_external": is_external,
            "is_disabled": disabled,
            "mfa_enabled": True,
            "last_active_at": None if days_ago is None else {"$days_ago": days_ago},
        },
        "application": {"type": "okta", "name": "Okta"},
        "roles": [],
    }


# Active external users who are stale or never signed in, beside every near
# miss an unscoped or naive policy gets wrong: a recent contractor, a disabled
# one, a stale employee, and a stale guest in another app. "Stale" is 400 days
# and "recent" 3, so any threshold an intent names (30, 90, 365) agrees.
OKTA_STALE_EXTERNAL_FIXTURES: dict[str, Any] = {
    "rows": [
        _okta_user("stale-contractor-id", "pat@vendor.example.com", is_external=True, days_ago=400),
        _okta_user("never-signed-in-id", "lee@vendor.example.com", is_external=True, days_ago=None),
        _okta_user("recent-contractor-id", "sam@vendor.example.com", is_external=True, days_ago=3),
        _okta_user("disabled-contractor-id", "kim@vendor.example.com", is_external=True, days_ago=200, disabled=True),
        _okta_user("stale-employee-id", "ada@acme.example.com", is_external=False, days_ago=400),
        {
            **_okta_user("github-guest-id", "guest@vendor.example.com", is_external=True, days_ago=400),
            "application": {"type": "github", "name": "GitHub"},
        },
    ],
    "expected_match_subject_ids": ["never-signed-in-id", "stale-contractor-id"],
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

_DAYS_IN_INTENT = re.compile(r"(\d+)\s*days?", re.IGNORECASE)


def _pack_policy_source(pack: str, filename: str) -> str:
    source = (get_packs_dir() / pack / "policies" / filename).read_text()
    lines = source.splitlines()
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    return "\n".join(lines).strip() + "\n"


def _cross_app_template_source(filename: str, days_constant: str, default_days: int) -> Any:
    """A template whose source is the shipped cross-app policy with the
    intent's day threshold substituted and a POLICY_ID derived from the intent."""

    def factory(intent: str) -> str:
        source = _pack_policy_source("cross-app", filename)
        match = _DAYS_IN_INTENT.search(intent)
        days = int(match.group(1)) if match else default_days
        source = re.sub(rf"^{days_constant} = \d+$", f"{days_constant} = {days}", source, count=1, flags=re.MULTILINE)
        return re.sub(r'^POLICY_ID = "[^"]+"', f'POLICY_ID = "{_slug_from_intent(intent)}"', source, count=1, flags=re.M)

    return factory


_CROSS_APP_CONTRACTOR_DORMANT = re.compile(
    r"(?=.*\b(contractors?|vendors?|contingent|partners?)\b)"
    r"(?=.*(inactive|dormant|stale|unused|signed? ?in|logged? ?in|log ?in|login|sign-?in|activity|\d+\s*days))",
    re.IGNORECASE | re.DOTALL,
)
_CROSS_APP_DEPARTED_OUTLIVED = re.compile(
    r"(?=.*\b(disabled|deprovisioned|deactivated|departed|offboarded|terminated|left)\b)"
    r"(?=.*(still|remain|survive|enabled|active|other app|another app|elsewhere|any app))"
    r"(?=.*(\d+\s*days|week|older|longer|more than|after|grace))",
    re.IGNORECASE | re.DOTALL,
)
_CROSS_APP_ADMIN_NO_IDP_MFA = re.compile(
    r"(?=.*\b(admins?|administrators?|owners?|privileged)\b)"
    r"(?=.*(without|no|missing|lack(s|ing)?)\s+(mfa|2fa|multi-?factor|two-?factor))"
    r"(?=.*(idp|identity provider|okta|google|any app|another app|other app|elsewhere|across))",
    re.IGNORECASE | re.DOTALL,
)
# "Everywhere" is the whole person; "any app" / "that app" is per account and
# belongs to the contractor-dormant set, so those words are deliberately absent.
_CROSS_APP_DORMANT_EVERYWHERE = re.compile(
    r"(?=.*(inactive|dormant|stale|unused|signed? ?in|logged? ?in|activity))"
    r"(?=.*(everywhere|every app|all apps|all connected|in all|no app|anywhere))",
    re.IGNORECASE | re.DOTALL,
)
_CROSS_APP_NEVER_SIGNED_IN = re.compile(
    r"(?=.*never\s+(signed|logged|log|sign)[\s-]*(in|on)|never used)(?=.*(created|provisioned|creation|days|weeks))",
    re.IGNORECASE | re.DOTALL,
)
_CROSS_APP_SENSITIVE_OAUTH = re.compile(
    r"(?=.*\b(contractors?|vendors?|guests?|external|contingent)\b)(?=.*(oauth|consent|third[- ]party|scopes?))",
    re.IGNORECASE | re.DOTALL,
)
_CROSS_APP_PRIVILEGE_EVENT = re.compile(
    r"(?=.*\b(granted|grant|grants|made|promoted|assigned)\b)(?=.*\b(admin|privilege|owner|role)\b)"
    r"(?=.*(disabled|deprovisioned|departed|offboarded|terminated|left))",
    re.IGNORECASE | re.DOTALL,
)
_CROSS_APP_SOD = re.compile(r"separation of duties|\bsod\b|(?=.*\bboth\b)(?=.*\badmin)", re.IGNORECASE | re.DOTALL)
_CROSS_APP_GROUP = re.compile(
    r"(?=.*\b(groups?|org unit|ou)\b)(?=.*\b(admins?|administrators?|owners?|privileged)\b)", re.IGNORECASE | re.DOTALL
)

INTENT_TEMPLATES: tuple[IntentTemplate, ...] = (
    IntentTemplate(
        name="cross-app-contractor-dormant-in-app",
        resource_type="identity",
        connector=CROSS_APP_CONNECTOR,
        pattern=_CROSS_APP_CONTRACTOR_DORMANT,
        source_factory=_cross_app_template_source("cross_app_contractor_dormant_in_app.py", "STALE_DAYS", 30),
        fixtures=CROSS_APP_FIXTURE_SETS["cross-app-contractor-dormant-in-app"],
    ),
    IntentTemplate(
        name="cross-app-departed-account-outlived-offboarding",
        resource_type="identity",
        connector=CROSS_APP_CONNECTOR,
        pattern=_CROSS_APP_DEPARTED_OUTLIVED,
        source_factory=_cross_app_template_source("cross_app_departed_account_outlived_offboarding.py", "GRACE_DAYS", 7),
        fixtures=CROSS_APP_FIXTURE_SETS["cross-app-departed-account-outlived-offboarding"],
    ),
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


@dataclass(frozen=True)
class IntentFixtures:
    """Fixtures whose expected matches are right for intents like ``pattern``.

    The LLM path has no template, so without this every Okta identity draft
    was tested against the admin-without-MFA pair: a correct policy for any
    other intent failed it, and the repair turn was told to break the policy
    until it matched.
    """

    name: str
    connector: str
    resource_type: str
    pattern: re.Pattern[str]
    fixtures: dict[str, Any]


INTENT_FIXTURES: tuple[IntentFixtures, ...] = (
    # Cross-application intents first: a cross-app scope only considers these.
    *(
        IntentFixtures(
            name=slug,
            connector=CROSS_APP_CONNECTOR,
            resource_type=resource_type,
            pattern=pattern,
            fixtures=CROSS_APP_FIXTURE_SETS[slug],
        )
        for slug, resource_type, pattern in (
            ("cross-app-contractor-dormant-in-app", "identity", _CROSS_APP_CONTRACTOR_DORMANT),
            ("cross-app-departed-account-outlived-offboarding", "identity", _CROSS_APP_DEPARTED_OUTLIVED),
            ("cross-app-admin-without-idp-mfa", "identity", _CROSS_APP_ADMIN_NO_IDP_MFA),
            ("cross-app-person-dormant-everywhere", "identity", _CROSS_APP_DORMANT_EVERYWHERE),
            ("cross-app-never-signed-in-after-creation", "identity", _CROSS_APP_NEVER_SIGNED_IN),
            ("cross-app-contractor-sensitive-oauth-consent", "identity", _CROSS_APP_SENSITIVE_OAUTH),
            ("cross-app-privilege-granted-to-disabled-idp-user", "event", _CROSS_APP_PRIVILEGE_EVENT),
            ("cross-app-separation-of-duties", "identity", _CROSS_APP_SOD),
            ("cross-app-group-scoped-privilege", "identity", _CROSS_APP_GROUP),
        )
    ),
    IntentFixtures(
        name="okta-stale-external-users",
        connector="okta",
        resource_type="identity",
        pattern=re.compile(
            r"(?=.*\b(external|contractors?|guests?|vendors?|third[- ]part(y|ies)|non[- ]employees?)\b)"
            r"(?=.*(inactive|dormant|stale|unused|never|signed? ?in|logged? ?in|log ?in|login|sign-in|activity|\d+\s*days))",
            re.IGNORECASE | re.DOTALL,
        ),
        fixtures=OKTA_STALE_EXTERNAL_FIXTURES,
    ),
    *(
        IntentFixtures(
            name=template.name,
            connector=template.connector or "",
            resource_type=template.resource_type,
            pattern=template.pattern,
            fixtures=template.fixtures,
        )
        for template in INTENT_TEMPLATES
        if template.connector
    ),
)


def _effective_connector(intent: str, connector_hint: str | None, scope: str | None) -> str | None:
    """The connector whose templates and fixtures apply: ``cross_app`` for a
    cross-application scope, else the hinted or named application."""
    resolution = resolve_scope(intent, connector_hint=connector_hint, scope=scope)
    if resolution.scope == SCOPE_CROSS_APP:
        return CROSS_APP_CONNECTOR
    return resolution.focus_connector


def fixtures_for_intent(
    intent: str, *, connector_hint: str | None, resource_type: str | None, scope: str | None = None
) -> dict[str, Any] | None:
    """Fixtures whose expectations fit ``intent``, or None when nothing does
    (the caller then falls back to a generic scaffold and treats its fixture
    test as advisory).

    A cross-application scope only considers the cross-app sets; a single
    application only its own, since the rows are connector-shaped and an
    unscoped intent would rightly match the other-app row they expect it to skip.
    An intent that names no application and asks for no cross-app scope gets
    nothing: nothing can be said about rows it was not written for.
    """
    hint = normalize_connector_hint(connector_hint)
    if hint is None and scope is None:
        connector: str | None = None
        if resolve_scope(intent, connector_hint=None, scope=None).scope == SCOPE_CROSS_APP:
            connector = CROSS_APP_CONNECTOR
    else:
        connector = _effective_connector(intent, hint, scope)
    if connector is None:
        return None
    for entry in INTENT_FIXTURES:
        if entry.connector != connector:
            continue
        if resource_type and entry.resource_type != resource_type:
            continue
        if entry.pattern.search(intent):
            return entry.fixtures
    return None


def match_intent_template(
    intent: str,
    *,
    connector_hint: str | None = None,
    resource_type: str | None = None,
    scope: str | None = None,
) -> IntentTemplate | None:
    """Return a high-confidence template for known posture intents, else None.

    Scope is resolved first: a cross-application intent only sees the
    cross-app templates, so an Okta dormancy template cannot hijack
    "contractors who haven't signed into any app". A single-application
    intent sees the templates of the hinted application, or of the one it
    names ("Okta admins without MFA" with no hint still routes).
    """
    connector = _effective_connector(intent, connector_hint, scope)
    if connector is None:
        return None
    for template in INTENT_TEMPLATES:
        if resource_type and template.resource_type != resource_type:
            continue
        if template.connector != connector:
            continue
        if template.pattern.search(intent):
            return template
    return None


@dataclass(frozen=True)
class PackCatalog:
    """What a connector's reviewed pack policies read: the vocabulary a draft
    for that connector should use. Derived from the pack sources, so it cannot
    drift from what shipped policies actually reference."""

    connector: str
    privileged_roles: tuple[str, ...]
    setting_keys: tuple[str, ...]
    event_actions: tuple[str, ...]
    identity_fields: tuple[str, ...]
    policy_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "privileged_roles": list(self.privileged_roles),
            "tenant_setting_keys": list(self.setting_keys),
            "event_actions": list(self.event_actions),
            "identity_fields": list(self.identity_fields),
            "policy_count": self.policy_count,
        }


_CATALOG_CAP = 24


def _string_items(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [elt.value for elt in node.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
    return []


def _scan_pack_source(source: str, roles: set[str], keys: set[str], actions: set[str], fields: set[str]) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            items = _string_items(node.value)
            if name.endswith("ROLES"):
                roles.update(items)
            elif name.endswith("ACTIONS"):
                actions.update(items)
            elif name.endswith(("KEYS", "SETTINGS")):
                keys.update(items)
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Call):
            call = node.left
            receiver = None
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                receiver = call.func.value.id
            attr = call.func.attr if isinstance(call.func, ast.Attribute) else None
            key = call.args[0].value if call.args and isinstance(call.args[0], ast.Constant) else None
            literals = [c.value for c in node.comparators if isinstance(c, ast.Constant) and isinstance(c.value, str)]
            for comparator in node.comparators:
                literals.extend(_string_items(comparator))
            if attr == "get" and receiver == "setting" and key == "key":
                keys.update(literals)
            elif attr == "get" and receiver == "event" and key == "action":
                actions.update(literals)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            receiver = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            if receiver == "identity" and node.args and isinstance(node.args[0], ast.Constant):
                fields.add(str(node.args[0].value))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "startswith"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "key"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value + "*")


@functools.lru_cache(maxsize=16)
def _pack_catalog_cached(packs_dir: Path, connector: str) -> PackCatalog | None:
    pack = CONNECTOR_PACKS.get(connector)
    if pack is None:
        return None
    policies_dir = packs_dir / pack / "policies"
    if not policies_dir.is_dir():
        return None
    roles: set[str] = set()
    keys: set[str] = set()
    actions: set[str] = set()
    fields: set[str] = set()
    count = 0
    for path in sorted(policies_dir.glob("*.py")):
        try:
            source = path.read_text()
        except OSError:
            continue
        count += 1
        _scan_pack_source(source, roles, keys, actions, fields)
    return PackCatalog(
        connector=connector,
        privileged_roles=tuple(sorted(roles))[:_CATALOG_CAP],
        setting_keys=tuple(sorted(keys))[: _CATALOG_CAP * 2],
        event_actions=tuple(sorted(actions))[:_CATALOG_CAP],
        identity_fields=tuple(sorted(fields))[:_CATALOG_CAP],
        policy_count=count,
    )


def pack_catalog(connector: str | None) -> PackCatalog | None:
    """The vocabulary a connector's shipped pack uses, or None without a pack."""
    connector = normalize_connector_hint(connector)
    if not connector:
        return None
    return _pack_catalog_cached(get_packs_dir(), connector)


def few_shot_for_connector(connector: str | None, resource_type: str | None) -> str:
    """Return a short example policy for the LLM prompt."""
    connector = normalize_connector_hint(connector)
    if connector == CROSS_APP_CONNECTOR:
        return _pack_policy_source("cross-app", "cross_app_contractor_dormant_in_app.py")
    if connector != "okta":
        return ""
    if resource_type == "tenant_setting":
        return _okta_mfa_enroll_not_required_source("Example: Okta MFA enroll not required")
    if resource_type == "event":
        return """POLICY_ID = "okta-activity-mfa-disabled"
TITLE = "Okta MFA factor deactivation events"
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
    """Extra context injected into LLM prompts for a connected app, or for the
    cross-application scope."""
    from kestrel.policies.resource_schemas import CROSS_APP_CATALOG

    connector = normalize_connector_hint(connector)
    if connector == CROSS_APP_CONNECTOR:
        return CROSS_APP_CATALOG + "\n\nExample cross-application policy:\n" + few_shot_for_connector(connector, None)
    if connector == "okta":
        lines = [
            'Okta connector catalog (application.type == "okta"):',
            f"- Privileged admin role names (resource.roles[]): {', '.join(repr(r) for r in OKTA_PRIVILEGED_ROLES)}",
            f"- tenant_setting keys: {', '.join(OKTA_TENANT_SETTING_KEYS)}",
            f"- event.action values: {', '.join(OKTA_EVENT_ACTIONS)}",
            "- identity fields: email, display_name, mfa_enabled, is_disabled, is_external, worker_type, "
            "last_active_at, last_active_source, department, title, disabled_at",
            "- Return True if compliant; False opens a finding.",
        ]
        example = few_shot_for_connector("okta", resource_type)
        if example:
            lines.append("\nExample policy for this connector:\n" + example)
        return "\n".join(lines)
    catalog = pack_catalog(connector)
    if catalog is None:
        return ""
    lines = [f'{connector} connector catalog (application.type == "{connector}"), from its shipped pack:']
    if catalog.privileged_roles:
        lines.append(f"- Privileged role names (resource.roles[]): {', '.join(repr(r) for r in catalog.privileged_roles)}")
    if catalog.setting_keys:
        lines.append(f"- tenant_setting keys: {', '.join(catalog.setting_keys)}")
    if catalog.event_actions:
        lines.append(f"- event.action values: {', '.join(catalog.event_actions)}")
    if catalog.identity_fields:
        lines.append(f"- identity fields the pack reads: {', '.join(catalog.identity_fields)}")
    lines.append("- Return True if compliant; False opens a finding.")
    return "\n".join(lines)
