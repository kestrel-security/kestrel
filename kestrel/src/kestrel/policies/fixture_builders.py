# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Build cross-application fixture rows from a compact description of people.

A cluster policy reads one row per account, and every row of a person must
carry the same ``cluster``: the accounts, the identity-provider state, who the
representative is. Writing that by hand drifts (one row says the IdP is
disabled, its sibling says active), and the drift is invisible until a draft
passes its fixtures for the wrong reason. ``build_fixtures`` derives every
row from the person, the way ``dataload.attach_cluster_context`` derives it
from the directory.

Timestamps are ``{"$days_ago": n}`` so ``kestrel.policies.testing``
expands them against the evaluation clock; a negative ``n`` is in the future.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from kestrel.policies.vocabulary import IDP_APPLICATION_TYPES, PRIVILEGED_ROLE_HINTS, TRUSTED_ACTIVITY_SOURCES

APPLICATION_NAMES: dict[str, str] = {
    "okta": "Okta",
    "google_workspace": "Google Workspace",
    "github": "GitHub",
    "slack": "Slack",
}


def _days_ago(value: float | None) -> dict[str, float] | None:
    return None if value is None else {"$days_ago": value}


def _is_privileged(roles: Iterable[str]) -> bool:
    return any(hint in str(role).lower() for role in roles for hint in PRIVILEGED_ROLE_HINTS)


@dataclass(frozen=True)
class AccountSpec:
    """One account of a person in one application."""

    app_type: str
    days_ago: float | None = None
    source: str | None = "login"
    disabled: bool = False
    disabled_days_ago: float | None = None
    roles: tuple[str, ...] = ()
    mfa: bool | None = None
    external: bool = False
    expires_days: float | None = None
    groups: tuple[str, ...] = ()
    created_days_ago: float | None = 400
    oauth_grants: tuple[dict[str, Any], ...] = ()
    identity_type: str = "user"
    worker_type: str | None = None  # defaults to the person's
    subject_id: str | None = None


@dataclass(frozen=True)
class PersonSpec:
    key: str
    email: str | None
    accounts: tuple[AccountSpec, ...]
    worker_type: str = "employee"
    display_name: str | None = None
    department: str | None = None
    extra_identity: dict[str, Any] = field(default_factory=dict)


def account(app_type: str, **overrides: Any) -> AccountSpec:
    return AccountSpec(app_type=app_type, **overrides)


def person(key: str, email: str | None, *accounts: AccountSpec, **overrides: Any) -> PersonSpec:
    return PersonSpec(key=key, email=email, accounts=tuple(accounts), **overrides)


def _subject_id(spec: PersonSpec, acct: AccountSpec, index: int) -> str:
    if acct.subject_id:
        return acct.subject_id
    same_type = [a for a in spec.accounts if a.app_type == acct.app_type]
    suffix = f"-{index}" if len(same_type) > 1 else ""
    return f"{spec.key}-{acct.app_type}{suffix}"


def _cluster_account(spec: PersonSpec, acct: AccountSpec, subject_id: str) -> dict[str, Any]:
    roles = list(acct.roles)
    return {
        "identity_id": subject_id,
        "application_type": acct.app_type,
        "application_name": APPLICATION_NAMES.get(acct.app_type, acct.app_type),
        "application_display_name": APPLICATION_NAMES.get(acct.app_type, acct.app_type),
        "identity_type": acct.identity_type,
        "email": spec.email,
        "display_name": spec.display_name or spec.key.replace("-", " ").title(),
        "is_disabled": acct.disabled,
        "is_external": acct.external,
        "mfa_enabled": acct.mfa,
        "last_active_at": _days_ago(acct.days_ago),
        "last_active_source": acct.source if acct.days_ago is not None else None,
        "created_at_source": _days_ago(acct.created_days_ago),
        "disabled_at": _days_ago(acct.disabled_days_ago) if acct.disabled else None,
        "expires_at": _days_ago(-acct.expires_days) if acct.expires_days is not None else None,
        "worker_type": acct.worker_type or spec.worker_type,
        "department": spec.department,
        "title": None,
        "groups": list(acct.groups),
        "roles": roles,
        "privileged": _is_privileged(roles),
    }


def build_rows(people: Sequence[PersonSpec], *, idp_connected: bool = True) -> list[dict[str, Any]]:
    """One identity row per account, each carrying its person's cluster."""
    rows: list[dict[str, Any]] = []
    for spec in people:
        subject_ids = [_subject_id(spec, acct, index) for index, acct in enumerate(spec.accounts)]
        accounts = [_cluster_account(spec, acct, sid) for acct, sid in zip(spec.accounts, subject_ids, strict=True)]
        idp_accounts = [a for a in accounts if a["application_type"] in IDP_APPLICATION_TYPES]
        if not idp_accounts:
            idp_status = "absent"
        elif all(a["is_disabled"] for a in idp_accounts):
            idp_status = "disabled"
        else:
            idp_status = "active"
        cluster_worker_type, worker_source = "unknown", "none"
        for a in idp_accounts:
            if a["worker_type"] != "unknown":
                cluster_worker_type, worker_source = a["worker_type"], "idp"
                break
        if cluster_worker_type == "unknown":
            for a in accounts:
                if a["worker_type"] != "unknown":
                    cluster_worker_type, worker_source = a["worker_type"], "other"
                    break
        trusted = [
            (a["last_active_at"]["$days_ago"], a["last_active_source"])
            for a in accounts
            if a["last_active_at"] is not None
            and (a["last_active_source"] is None or a["last_active_source"] in TRUSTED_ACTIVITY_SOURCES)
        ]
        latest = min(trusted, key=lambda item: item[0]) if trusted else None
        # The representative prefers an identity-provider account, like the loader.
        representative = next(
            (a["identity_id"] for a in accounts if a["application_type"] in IDP_APPLICATION_TYPES),
            accounts[0]["identity_id"] if accounts else None,
        )
        for acct, sid, this_account in zip(spec.accounts, subject_ids, accounts, strict=True):
            identity = {
                "identity_type": acct.identity_type,
                "email": spec.email,
                "display_name": this_account["display_name"],
                "is_disabled": acct.disabled,
                "is_external": acct.external,
                "mfa_enabled": acct.mfa,
                "last_active_at": this_account["last_active_at"],
                "last_active_source": this_account["last_active_source"],
                "created_at_source": this_account["created_at_source"],
                "disabled_at": this_account["disabled_at"],
                "expires_at": this_account["expires_at"],
                "worker_type": this_account["worker_type"],
                "department": spec.department,
                "title": None,
                "manager_email": None,
                "attributes": {},
                **spec.extra_identity,
            }
            rows.append(
                {
                    "_subject_id": sid,
                    "_subject_type": "identity",
                    "identity": identity,
                    "application": {
                        "type": acct.app_type,
                        "name": APPLICATION_NAMES.get(acct.app_type, acct.app_type),
                    },
                    "roles": list(acct.roles),
                    "groups": list(acct.groups),
                    "oauth_grants": [dict(grant) for grant in acct.oauth_grants],
                    "privileged_application_types": sorted({a["application_type"] for a in accounts if a["privileged"]}),
                    "cluster": {
                        "accounts": [dict(a) for a in accounts],
                        "member_count": len(accounts),
                        "active_account_count": sum(1 for a in accounts if not a["is_disabled"]),
                        "application_types": sorted({a["application_type"] for a in accounts}),
                        "idp_status": idp_status,
                        "idp_application_types": sorted({a["application_type"] for a in idp_accounts}),
                        "privileged_application_types": sorted({a["application_type"] for a in accounts if a["privileged"]}),
                        "worker_type": cluster_worker_type,
                        "worker_type_source": worker_source,
                        "department": spec.department,
                        "last_active_at": _days_ago(latest[0]) if latest else None,
                        "last_active_source": latest[1] if latest else None,
                        "match_kind": "email" if len(accounts) > 1 else "self",
                        "idp_connected": idp_connected,
                        "representative_identity_id": representative,
                        "is_representative": sid == representative,
                    },
                    "org": {
                        "connected_application_types": sorted({a["application_type"] for a in accounts}),
                        "idp_application_types": sorted({a["application_type"] for a in idp_accounts}),
                        "idp_connected": idp_connected,
                        "company_email_domains": [],
                    },
                }
            )
    return rows


def build_fixtures(people: Sequence[PersonSpec], expected: Iterable[str], *, idp_connected: bool = True) -> dict[str, Any]:
    """``{"rows", "expected_match_subject_ids"}`` for a fixture file or an AI draft check."""
    return {"rows": build_rows(people, idp_connected=idp_connected), "expected_match_subject_ids": sorted(expected)}
