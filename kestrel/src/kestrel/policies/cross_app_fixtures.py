# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Fixture scenarios for the cross-application pack and the AI draft checks.

Each set is the people a policy must get right, written as ``PersonSpec``s so
every account row carries a consistent cluster (``fixture_builders``). The
pack's ``policies/fixtures/*.fixtures.json`` files are generated from here
(``scripts/gen-cross-app-fixtures.py``) and a unit test keeps them equal, so
the generator's intent fixtures, the shipped pack, and the deterministic
templates all judge a draft against the same rows.

Thresholds are far apart on purpose: "stale" is 400 days and "recent" is 3,
so any window an intent names (30, 90, 365) agrees with the expectations.
"""

from __future__ import annotations

from typing import Any

from kestrel.policies.fixture_builders import account, build_fixtures, person

STALE = 400
RECENT = 3

SENSITIVE_GRANT = {
    "oauth_application_name": "Mail Merge Pro",
    "publisher": "Unknown Vendor",
    "is_verified": False,
    "sensitive_scope_names": ["https://www.googleapis.com/auth/gmail.readonly"],
    "granted_at": {"$days_ago": 40},
    "last_used_at": {"$days_ago": 2},
}
BENIGN_GRANT = {
    "oauth_application_name": "Calendar Widget",
    "publisher": "Example Co",
    "is_verified": True,
    "sensitive_scope_names": [],
    "granted_at": {"$days_ago": 40},
    "last_used_at": {"$days_ago": 2},
}

CONTRACTOR_DORMANT_IN_APP = build_fixtures(
    [
        person(
            "stale-contractor",
            "pat@vendor.example",
            account("okta", days_ago=RECENT),
            account("github", days_ago=STALE, source="audit"),
            account("slack", days_ago=STALE, source="audit"),
            worker_type="contractor",
        ),
        person(
            "recent-contractor",
            "sam@vendor.example",
            account("okta", days_ago=RECENT),
            account("slack", days_ago=RECENT, source="audit"),
            worker_type="contractor",
        ),
        person(
            "disabled-stale-contractor",
            "kim@vendor.example",
            account("okta", days_ago=RECENT),
            account("slack", days_ago=STALE, source="audit", disabled=True),
            worker_type="contractor",
        ),
        person(
            "stale-employee",
            "ada@acme.example.com",
            account("okta", days_ago=STALE),
            account("slack", days_ago=STALE, source="audit"),
            worker_type="employee",
        ),
        person(
            "never-signed-in-contractor",
            "lee@vendor.example",
            account("okta", days_ago=RECENT),
            account("slack", days_ago=None),
            worker_type="contractor",
        ),
        person(
            "profile-only-contractor",
            "jo@vendor.example",
            account("okta", days_ago=RECENT),
            account("slack", days_ago=STALE, source="profile"),
            worker_type="contractor",
        ),
        person(
            "github-unobserved-contractor",
            "max@vendor.example",
            account("okta", days_ago=RECENT),
            account("github", days_ago=None),
            worker_type="contractor",
        ),
        person(
            "unknown-worker", "who@partner.example", account("slack", days_ago=STALE, source="audit"), worker_type="unknown"
        ),
        person("stale-contractor-idp", "ray@vendor.example", account("okta", days_ago=STALE), worker_type="contractor"),
        person(
            "stale-vendor",
            "vi@partner.example",
            account("okta", days_ago=RECENT),
            account("github", days_ago=STALE, source="audit"),
            worker_type="vendor_or_partner",
        ),
        person(
            "bot",
            None,
            account("slack", days_ago=STALE, source="audit", identity_type="service_account"),
            worker_type="service",
        ),
    ],
    [
        "stale-contractor-github",
        "stale-contractor-slack",
        "never-signed-in-contractor-slack",
        "stale-contractor-idp-okta",
        "stale-vendor-github",
    ],
)

DEPARTED_ACCOUNT_OUTLIVED_OFFBOARDING = build_fixtures(
    [
        person(
            "long-gone",
            "kj@acme.example.com",
            account("okta", disabled=True, disabled_days_ago=30),
            account("slack", days_ago=STALE),
            account("github", days_ago=None),
        ),
        person(
            "just-disabled",
            "al@acme.example.com",
            account("okta", disabled=True, disabled_days_ago=2),
            account("slack", days_ago=RECENT),
        ),
        person(
            "no-timestamp",
            "bo@acme.example.com",
            account("okta", disabled=True, disabled_days_ago=None),
            account("slack", days_ago=RECENT),
        ),
        person("active-idp", "cy@acme.example.com", account("okta", days_ago=RECENT), account("slack", days_ago=RECENT)),
        person(
            "survivor-disabled",
            "di@acme.example.com",
            account("okta", disabled=True, disabled_days_ago=30),
            account("slack", disabled=True),
        ),
        person(
            "bot",
            None,
            account("okta", disabled=True, disabled_days_ago=30, identity_type="service_account"),
            account("slack", identity_type="service_account"),
            worker_type="service",
        ),
        person("no-idp", "ed@acme.example.com", account("github", days_ago=RECENT)),
    ],
    ["long-gone-slack", "long-gone-github"],
)

ADMIN_WITHOUT_IDP_MFA = build_fixtures(
    [
        person(
            "admin-no-mfa",
            "ann@acme.example.com",
            account("okta", mfa=False),
            account("github", roles=("organization_admin",)),
        ),
        person(
            "admin-with-mfa",
            "ben@acme.example.com",
            account("okta", mfa=True),
            account("github", roles=("organization_admin",)),
        ),
        person(
            "mfa-unknown",
            "cat@acme.example.com",
            account("okta", mfa=None),
            account("github", roles=("organization_admin",)),
        ),
        person("no-mfa-not-admin", "dan@acme.example.com", account("okta", mfa=False), account("github")),
        person(
            "no-mfa-admin-disabled-app",
            "eve@acme.example.com",
            account("okta", mfa=False),
            account("github", roles=("organization_admin",), disabled=True),
        ),
        person("no-idp-admin", "fay@acme.example.com", account("github", roles=("organization_admin",))),
        person(
            "idp-admin-itself-no-mfa", "gus@acme.example.com", account("okta", mfa=False, roles=("Super Administrator",))
        ),
        person(
            "disabled-idp",
            "hal@acme.example.com",
            account("okta", mfa=False, disabled=True),
            account("github", roles=("organization_admin",)),
        ),
    ],
    ["admin-no-mfa-okta", "idp-admin-itself-no-mfa-okta"],
)

PERSON_DORMANT_EVERYWHERE = build_fixtures(
    [
        person(
            "gone-quiet",
            "ivy@acme.example.com",
            account("okta", days_ago=200),
            account("slack", days_ago=200, source="audit"),
        ),
        person(
            "active-somewhere",
            "jan@acme.example.com",
            account("okta", days_ago=200),
            account("slack", days_ago=RECENT, source="audit"),
        ),
        person("unknown-somewhere", "kai@acme.example.com", account("okta", days_ago=200), account("github", days_ago=None)),
        person(
            "profile-only",
            "lou@acme.example.com",
            account("okta", days_ago=200),
            account("slack", days_ago=RECENT, source="profile"),
        ),
        person(
            "all-disabled",
            "mia@acme.example.com",
            account("okta", days_ago=200, disabled=True),
            account("slack", days_ago=200, disabled=True),
        ),
        person("never-anywhere", "ned@acme.example.com", account("okta", days_ago=None), account("slack", days_ago=None)),
        person(
            "bot",
            None,
            account("okta", days_ago=200, identity_type="service_account"),
            worker_type="service",
        ),
    ],
    ["gone-quiet-okta", "never-anywhere-okta"],
)

NEVER_SIGNED_IN_AFTER_CREATION = build_fixtures(
    [
        person("provisioned-never-used", "oli@acme.example.com", account("slack", days_ago=None, created_days_ago=60)),
        person("brand-new", "pam@acme.example.com", account("slack", days_ago=None, created_days_ago=5)),
        person("used", "quy@acme.example.com", account("slack", days_ago=RECENT, created_days_ago=60)),
        person("unknown-created", "rae@acme.example.com", account("slack", days_ago=None, created_days_ago=None)),
        person("github-never", "sid@acme.example.com", account("github", days_ago=None, created_days_ago=60)),
        person(
            "profile-only", "tam@acme.example.com", account("slack", days_ago=STALE, source="profile", created_days_ago=60)
        ),
        person("disabled", "una@acme.example.com", account("slack", days_ago=None, created_days_ago=60, disabled=True)),
    ],
    ["provisioned-never-used-slack"],
)

CONTRACTOR_SENSITIVE_OAUTH_CONSENT = build_fixtures(
    [
        person(
            "contractor-consented",
            "pat@vendor.example",
            account("okta"),
            account("google_workspace", oauth_grants=(SENSITIVE_GRANT,)),
            worker_type="contractor",
        ),
        person(
            "contractor-benign",
            "sam@vendor.example",
            account("okta"),
            account("google_workspace", oauth_grants=(BENIGN_GRANT,)),
            worker_type="contractor",
        ),
        person("employee-consented", "ada@acme.example.com", account("google_workspace", oauth_grants=(SENSITIVE_GRANT,))),
        person(
            "guest-consented",
            "guest@partner.example",
            account("slack", external=True, oauth_grants=(SENSITIVE_GRANT,)),
            worker_type="guest",
        ),
        person(
            "unknown-consented",
            "who@partner.example",
            account("google_workspace", oauth_grants=(SENSITIVE_GRANT,)),
            worker_type="unknown",
        ),
    ],
    ["contractor-consented-google_workspace", "guest-consented-slack"],
)

SEPARATION_OF_DUTIES = build_fixtures(
    [
        person(
            "idp-and-github-admin",
            "ann@acme.example.com",
            account("okta", roles=("Super Administrator",)),
            account("github", roles=("organization_admin",)),
        ),
        person(
            "github-and-slack-admin",
            "ben@acme.example.com",
            account("github", roles=("organization_admin",)),
            account("slack", roles=("Owner",)),
        ),
        person("idp-admin-only", "cat@acme.example.com", account("okta", roles=("Super Administrator",)), account("github")),
        person(
            "disabled-github-admin",
            "dan@acme.example.com",
            account("okta", roles=("Super Administrator",)),
            account("github", roles=("organization_admin",), disabled=True),
        ),
        person(
            "gws-and-slack",
            "eve@acme.example.com",
            account("google_workspace", roles=("super_admin",)),
            account("slack", roles=("Admin",)),
        ),
    ],
    ["idp-and-github-admin-okta", "gws-and-slack-google_workspace"],
)

GROUP_SCOPED_PRIVILEGE = build_fixtures(
    [
        person(
            "contractor-group-admin-elsewhere",
            "pat@vendor.example",
            account("okta", groups=("contractors-emea",)),
            account("github", roles=("organization_admin",)),
        ),
        person(
            "contractor-group-no-admin", "sam@vendor.example", account("okta", groups=("contractors",)), account("github")
        ),
        person(
            "staff-group-admin",
            "ada@acme.example.com",
            account("okta", groups=("engineering",)),
            account("github", roles=("organization_admin",)),
        ),
        person(
            "contractor-group-admin-here-only",
            "ray@vendor.example",
            account("okta", groups=("contractors",), roles=("Super Administrator",)),
        ),
        person(
            "gws-ou",
            "vi@partner.example",
            account("google_workspace", groups=("/Contractors",)),
            account("slack", roles=("Owner",)),
        ),
        person(
            "disabled-member",
            "kim@vendor.example",
            account("okta", groups=("contractors",), disabled=True),
            account("github", roles=("organization_admin",)),
        ),
    ],
    ["contractor-group-admin-elsewhere-okta", "gws-ou-google_workspace"],
)


def _event_row(subject_id: str, *, action: str, days_ago: float, target: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "_subject_id": subject_id,
        "_subject_type": "event",
        "event": {
            "action": action,
            "action_category": "privilege" if action.startswith("privilege") else "auth",
            "actor_email": "admin@acme.example.com",
            "actor_provider_id": "1",
            "target_email": (target or {}).get("email"),
            "target_type": "identity",
            "target_provider_id": "2",
            "occurred_at": {"$days_ago": days_ago},
            "summary": f"{action} on {(target or {}).get('email') or 'nobody'}",
            "attributes": {"permission": "admin"},
            "actor": {"identity_id": "admin", "email": "admin@acme.example.com", "cluster_idp_status": "active"},
            "target": target,
        },
        "application": {"type": "github", "name": "GitHub"},
    }


def _target(email: str, idp_status: str) -> dict[str, Any]:
    return {
        "identity_id": email,
        "email": email,
        "display_name": email.split("@")[0].title(),
        "identity_type": "user",
        "is_disabled": False,
        "is_external": False,
        "worker_type": "unknown",
        "privileged": False,
        "cluster_worker_type": "employee",
        "cluster_idp_status": idp_status,
        "representative_identity_id": email,
    }


PRIVILEGE_GRANTED_TO_DISABLED_IDP_USER: dict[str, Any] = {
    "rows": [
        _event_row(
            "grant-to-departed", action="privilege.grant", days_ago=2, target=_target("kj@acme.example.com", "disabled")
        ),
        _event_row(
            "grant-to-active", action="privilege.grant", days_ago=2, target=_target("ada@acme.example.com", "active")
        ),
        _event_row(
            "old-grant-to-departed", action="privilege.grant", days_ago=60, target=_target("kj@acme.example.com", "disabled")
        ),
        _event_row("grant-no-target", action="privilege.grant", days_ago=2, target=None),
        _event_row(
            "other-action-departed", action="mfa.disable", days_ago=2, target=_target("kj@acme.example.com", "disabled")
        ),
        _event_row("grant-no-idp", action="privilege.grant", days_ago=2, target=_target("ed@acme.example.com", "absent")),
    ],
    "expected_match_subject_ids": ["grant-to-departed"],
}

#: Policy slug -> the fixtures the pack ships for it.
CROSS_APP_FIXTURE_SETS: dict[str, dict[str, Any]] = {
    "cross-app-contractor-dormant-in-app": CONTRACTOR_DORMANT_IN_APP,
    "cross-app-departed-account-outlived-offboarding": DEPARTED_ACCOUNT_OUTLIVED_OFFBOARDING,
    "cross-app-admin-without-idp-mfa": ADMIN_WITHOUT_IDP_MFA,
    "cross-app-person-dormant-everywhere": PERSON_DORMANT_EVERYWHERE,
    "cross-app-never-signed-in-after-creation": NEVER_SIGNED_IN_AFTER_CREATION,
    "cross-app-contractor-sensitive-oauth-consent": CONTRACTOR_SENSITIVE_OAUTH_CONSENT,
    "cross-app-privilege-granted-to-disabled-idp-user": PRIVILEGE_GRANTED_TO_DISABLED_IDP_USER,
    "cross-app-separation-of-duties": SEPARATION_OF_DUTIES,
    "cross-app-group-scoped-privilege": GROUP_SCOPED_PRIVILEGE,
}
