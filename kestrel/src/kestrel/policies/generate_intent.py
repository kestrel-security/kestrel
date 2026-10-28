# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""What an intent asks for, before any model sees it.

Two things are decided here deterministically, so they work with no provider
configured and cannot be talked out of by a draft:

* the **scope**: one connected application, or every connected application
  at once (a cross-application policy that reads the ``cluster``);
* the **analysis**: the subject, the conditions, the threshold in days, whether
  the finding is per account or per person, which row fields the policy will
  need, and therefore which capability keys it must ``REQUIRE``.

The analysis is rendered as a plan in the prompt, used to pick fixtures and
templates, and returned to the operator so they can see what the generator
understood before trusting the draft.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

SCOPE_SINGLE_APP = "single_app"
SCOPE_CROSS_APP = "cross_app"
SCOPES = (SCOPE_SINGLE_APP, SCOPE_CROSS_APP)

#: The pseudo-connector a caller names to ask for a cross-application draft.
CROSS_APP_CONNECTOR = "cross_app"

_CONNECTOR_ALIASES: dict[str, str] = {
    "okta": "okta",
    "idp": "okta",
    "cross_app": CROSS_APP_CONNECTOR,
    "crossapp": CROSS_APP_CONNECTOR,
    "all": CROSS_APP_CONNECTOR,
    "any": CROSS_APP_CONNECTOR,
    "all_apps": CROSS_APP_CONNECTOR,
    "any_app": CROSS_APP_CONNECTOR,
    "all_connected_apps": CROSS_APP_CONNECTOR,
    "everywhere": CROSS_APP_CONNECTOR,
    "google": "google_workspace",
    "gws": "google_workspace",
}


def normalize_connector_hint(hint: str | None) -> str | None:
    if not hint:
        return None
    key = hint.strip().lower().replace(" ", "_").replace("-", "_")
    return _CONNECTOR_ALIASES.get(key, key)


#: Words in an intent that name a connector, so an unhinted single-app intent
#: still gets its catalog and templates.
CONNECTOR_WORDS: dict[str, tuple[str, ...]] = {
    "okta": ("okta",),
    "github": ("github", "gh org"),
    "google_workspace": ("google workspace", "gws", "google admin", "gsuite", "g suite"),
    "slack": ("slack",),
}

# Wording that can only mean several applications. It overrides a selected
# application, which then becomes the focus.
_STRONG_CROSS_APP = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(any|all|every|each|other|another|multiple|several|two or more)\s+(connected\s+)?"
        r"(app|apps|application|applications|saas)\b",
        r"\bthat app\b",
        r"\bacross (apps|applications|all apps|every app|connected apps|saas)\b",
        r"\belsewhere\b",
        r"\bin one app\b",
        r"\bsame person\b",
        r"\bseparation of duties\b",
        r"\bdormant everywhere\b",
        r"\b(no|without|missing)\s+(an\s+)?(idp|identity[- ]provider)\s+account\b",
    )
)
# "Install any app", "authorize other apps": the apps are third-party
# integrations inside one tenant, not the connected applications.
_THIRD_PARTY_APP_VERB = re.compile(
    r"\b(install|installs|installing|add|adds|authorize|authorizes|approve|approves|connect|connects|"
    r"request|requests|integrate|integrates|use|uses|grant|grants)\s+$",
    re.IGNORECASE,
)

# Wording that suggests several applications but appears in ordinary
# single-application intents too ("SSO through the identity provider",
# "channels shared across workspaces", "IdP discovery rules"). It flips the
# scope only when no application is selected.
_CONTEXTUAL_CROSS_APP = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bacross\b",
        r"\bidentity[- ]provider\b",
        r"\bidp\b",
        r"\b(disabled|deprovisioned|deactivated|suspended)\s+in\s+(okta|google|the idp|the identity provider)\b",
        r"\bcorrelated\b",
        r"\b(other|another|multiple)\s+tenants?\b",
    )
)
_WEAK_CROSS_APP = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bcontractors?\b",
        r"\bvendors?\b",
        r"\bpartners?\b",
        r"\bdeparted\b",
        r"\boffboard",
        r"\bleft the (company|org|organization)\b",
        r"\bservice accounts?\s+(without|with no|missing)\s+(an\s+)?owner\b",
    )
)


def named_connectors(intent: str) -> list[str]:
    """Connectors the intent mentions by name, in order of first mention."""
    lowered = intent.lower()
    found: list[tuple[int, str]] = []
    for connector, words in CONNECTOR_WORDS.items():
        positions = [lowered.find(word) for word in words if word in lowered]
        if positions:
            found.append((min(positions), connector))
    return [connector for _, connector in sorted(found)]


@dataclass(frozen=True)
class ScopeResolution:
    scope: str
    source: str  # request | connector_hint | intent_wording | default
    focus_connector: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_scope(intent: str, *, connector_hint: str | None = None, scope: str | None = None) -> ScopeResolution:
    """Decide between one application and all of them.

    Precedence: an explicit ``scope``; the ``cross_app`` pseudo-connector;
    explicit cross-application wording ("any app", "every app", "elsewhere",
    "that app") even when an application is selected, which then becomes the
    focus; contextual wording ("across", "identity provider") only when no
    application is selected; weak wording ("contractor", "departed") only when
    no application is selected and none is named; otherwise one application.
    """
    hint = normalize_connector_hint(connector_hint)
    named = named_connectors(intent)
    focus = hint if hint and hint != CROSS_APP_CONNECTOR else (named[0] if named else None)
    if scope in SCOPES:
        return ScopeResolution(scope, "request", None if scope == SCOPE_CROSS_APP and not hint else focus, "requested")
    if hint == CROSS_APP_CONNECTOR:
        return ScopeResolution(SCOPE_CROSS_APP, "connector_hint", focus, "connector hint is cross_app")
    for pattern in _STRONG_CROSS_APP:
        for strong in pattern.finditer(intent):
            if _THIRD_PARTY_APP_VERB.search(intent[: strong.start()]):
                continue  # "install any app": third-party apps, not connected ones
            return ScopeResolution(SCOPE_CROSS_APP, "intent_wording", focus, f"intent says {strong.group(0)!r}")
    if not hint:
        for pattern in _CONTEXTUAL_CROSS_APP:
            match = pattern.search(intent)
            if match:
                return ScopeResolution(SCOPE_CROSS_APP, "intent_wording", focus, f"intent says {match.group(0)!r}")
    if not hint and not named:
        for pattern in _WEAK_CROSS_APP:
            match = pattern.search(intent)
            if match:
                return ScopeResolution(
                    SCOPE_CROSS_APP, "intent_wording", None, f"intent says {match.group(0)!r} and names no application"
                )
    source = "connector_hint" if hint else ("intent_wording" if named else "default")
    return ScopeResolution(SCOPE_SINGLE_APP, source, focus, "one application")


# -- analysis -------------------------------------------------------------------

#: Condition name -> (pattern, row fields the policy will read, resource type it implies or None).
_CONDITIONS: tuple[tuple[str, re.Pattern[str], tuple[str, ...], str | None], ...] = (
    (
        "stale_activity",
        re.compile(
            r"(haven'?t|has ?n'?t|have not|has not|not|never|no)\s+(been\s+)?(signed|logged|log|sign)[\s-]*(in|on)"
            r"|\binactive\b|\bdormant\b|\bstale\b|\bunused\b|\bidle\b|no (recent )?(sign-?in|login|activity)",
            re.IGNORECASE,
        ),
        ("identity.last_active_at", "identity.last_active_source", "cluster.accounts[].last_active_at"),
        None,
    ),
    (
        "never_used",
        re.compile(r"\bnever\s+(signed|logged|log|sign)[\s-]*(in|on)|\bnever used\b", re.IGNORECASE),
        ("identity.last_active_at", "identity.created_at_source"),
        None,
    ),
    (
        "idp_disabled",
        re.compile(
            r"\b(disabled|deprovisioned|deactivated|suspended|terminated|departed|offboarded|left)\b",
            re.IGNORECASE,
        ),
        ("cluster.idp_status", "cluster.accounts[].is_disabled", "cluster.accounts[].disabled_at"),
        None,
    ),
    (
        "mfa_missing",
        re.compile(
            r"(without|no|missing|lack(s|ing)?|not enrolled in)\s+(mfa|2fa|multi-?factor|two-?factor)", re.IGNORECASE
        ),
        ("identity.mfa_enabled", "cluster.accounts[].mfa_enabled"),
        None,
    ),
    (
        "privileged",
        re.compile(r"\b(admins?|administrators?|owners?|privileged|super ?admins?|org admin)\b", re.IGNORECASE),
        ("roles", "cluster.accounts[].privileged", "cluster.privileged_application_types"),
        None,
    ),
    (
        "sensitive_oauth",
        re.compile(r"\boauth\b|\bconsent(ed)?\b|third[- ]party app|\bscopes?\b|\bauthoriz", re.IGNORECASE),
        ("oauth_grants[].sensitive_scope_names", "oauth_grants[].oauth_application_name"),
        None,
    ),
    (
        "no_expiry",
        re.compile(r"(no|without|missing)\s+(an\s+)?expir", re.IGNORECASE),
        ("identity.expires_at",),
        None,
    ),
    (
        "group_member",
        re.compile(r"\bgroups?\b|\borg unit\b|\bou\b|\bteam\b", re.IGNORECASE),
        ("groups",),
        None,
    ),
    (
        "created",
        re.compile(r"\bcreated\b|\bprovisioned\b|\bsince creation\b|after creation", re.IGNORECASE),
        ("identity.created_at_source",),
        None,
    ),
    (
        "service_account_owner",
        re.compile(r"service accounts?\s+(without|with no|missing)\s+(an\s+)?owner", re.IGNORECASE),
        ("identity.identity_type",),
        None,
    ),
    (
        "separation_of_duties",
        re.compile(r"separation of duties|\bsod\b|\bboth\b.*\band\b.*\badmin", re.IGNORECASE),
        ("cluster.privileged_application_types", "cluster.accounts[].privileged"),
        None,
    ),
    (
        "privilege_event",
        re.compile(
            r"(?=.*\b(granted|grants?|grant|promoted|assigned)\b)(?=.*\b(admin|privilege|owner|role)\b)"
            r"|\bmade (an )?admin\b|privilege\.grant",
            re.IGNORECASE | re.DOTALL,
        ),
        ("event.action", "event.target.cluster_idp_status", "event.occurred_at"),
        "event",
    ),
)

_EVENT_WORDING = re.compile(
    r"\b(events?|audit|logs?|logged|when|whenever|alert|was granted|were granted|is granted|gets granted|"
    r"granted (in|to)|grants? (in|to)|promoted|made (an )?admin)\b",
    re.IGNORECASE,
)

_SUBJECTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "contractor",
        re.compile(r"\bcontractors?\b|\bcontingent\b|\bvendors?\b|\bpartners?\b|\bconsultants?\b", re.IGNORECASE),
    ),
    ("guest", re.compile(r"\bguests?\b|\boutside collaborators?\b|\bexternal (users?|accounts?)\b", re.IGNORECASE)),
    ("employee", re.compile(r"\bemployees?\b|\bstaff\b|\bfull[- ]time\b", re.IGNORECASE)),
    ("service", re.compile(r"\bservice accounts?\b|\bbots?\b|\bapi tokens?\b", re.IGNORECASE)),
)

_PER_PERSON = re.compile(
    r"\b(per person|one finding per person|same person|people who|person who|everywhere|in every app|across all)\b"
    r"|separation of duties|\bsod\b",
    re.IGNORECASE,
)
_DAYS = re.compile(r"(\d+)\s*(day|days|d)\b", re.IGNORECASE)
_WEEKS = re.compile(r"(\d+)\s*(week|weeks|w)\b", re.IGNORECASE)
_MONTHS = re.compile(r"(\d+)\s*(month|months)\b", re.IGNORECASE)

#: Row field (as documented in the schemas) -> the capability a connector must provide.
FIELD_CAPABILITIES: dict[str, str] = {
    "identity.last_active_at": "identity:last_sign_in",
    "identity.last_active_source": "identity:last_sign_in",
    "cluster.accounts[].last_active_at": "identity:last_sign_in",
    "cluster.last_active_at": "identity:last_sign_in",
    "identity.worker_type": "identity:worker_type",
    "cluster.worker_type": "identity:worker_type",
    "groups": "identity:groups",
    "cluster.accounts[].groups": "identity:groups",
    "identity.expires_at": "identity:expires_at",
    "identity.disabled_at": "identity:disabled_at",
    "cluster.accounts[].disabled_at": "identity:disabled_at",
    "identity.department": "identity:department",
    "identity.title": "identity:department",
    "identity.manager_email": "identity:department",
    "oauth_grants[].sensitive_scope_names": "identity:oauth_grants",
    "oauth_grants[].oauth_application_name": "identity:oauth_grants",
}


@dataclass(frozen=True)
class IntentAnalysis:
    scope: str
    scope_source: str
    scope_reason: str
    focus_connector: str | None
    resource_type: str | None
    subject: dict[str, Any]
    conditions: list[str]
    days: int | None
    per: str  # account | person
    fields_needed: list[str]
    requires: list[str]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _threshold_days(intent: str) -> int | None:
    match = _DAYS.search(intent)
    if match:
        return int(match.group(1))
    match = _WEEKS.search(intent)
    if match:
        return int(match.group(1)) * 7
    match = _MONTHS.search(intent)
    if match:
        return int(match.group(1)) * 30
    return None


def analyze_intent(
    intent: str,
    *,
    connector_hint: str | None = None,
    resource_type: str | None = None,
    scope: str | None = None,
) -> IntentAnalysis:
    """A deterministic reading of the intent: no provider, no guessing beyond
    the keyword tables, and every field it names maps to a capability key."""
    resolution = resolve_scope(intent, connector_hint=connector_hint, scope=scope)
    conditions: list[str] = []
    fields: list[str] = []
    implied_type: str | None = None
    for name, pattern, condition_fields, implied in _CONDITIONS:
        if pattern.search(intent):
            conditions.append(name)
            fields.extend(f for f in condition_fields if f not in fields)
            implied_type = implied_type or implied
    # "Users assigned the admin role without MFA" is about identities. An
    # event resource type is only inferred when the intent is about something
    # that happened: an event, a log entry, a grant at a point in time.
    if implied_type == "event" and not _EVENT_WORDING.search(intent):
        implied_type = None
    subject: dict[str, Any] = {"identity_type": "user"}
    for worker_type, pattern in _SUBJECTS:
        if pattern.search(intent):
            subject["worker_type"] = worker_type
            if worker_type == "service":
                subject["identity_type"] = "service_account"
            break
    if subject.get("worker_type") in ("contractor", "guest", "employee"):
        for name in ("identity.worker_type", "cluster.worker_type"):
            if name not in fields:
                fields.append(name)
    if "privileged" in conditions:
        subject["privileged"] = True
    days = _threshold_days(intent)
    per = "person" if (_PER_PERSON.search(intent) or "separation_of_duties" in conditions) else "account"
    requires = sorted({FIELD_CAPABILITIES[name] for name in fields if name in FIELD_CAPABILITIES})
    notes: list[str] = [resolution.reason]
    if resolution.scope == SCOPE_CROSS_APP and resolution.focus_connector:
        notes.append(f"{resolution.focus_connector} is the focus application; the policy still reads every application")
    if subject.get("worker_type") in ("contractor", "guest"):
        notes.append(
            "worker_type may be 'unknown' when neither the provider nor a classification rule says; "
            "decide what unknown means"
        )
    if "stale_activity" in conditions or "never_used" in conditions:
        notes.append("only trusted activity sources count; GitHub's audit log alone makes an account 'unknown', not dormant")
    return IntentAnalysis(
        scope=resolution.scope,
        scope_source=resolution.source,
        scope_reason=resolution.reason,
        focus_connector=resolution.focus_connector,
        resource_type=resource_type or implied_type,
        subject=subject,
        conditions=conditions,
        days=days,
        per=per,
        fields_needed=fields,
        requires=requires,
        notes=notes,
    )


def render_plan(analysis: IntentAnalysis) -> str:
    """The analysis as the plan preamble the draft prompt carries."""
    lines = [
        "Plan (from intent analysis; follow it):",
        f"- scope: {analysis.scope} ({analysis.scope_reason})",
        f"- finding per: {analysis.per}"
        + (" (gate with is_representative(resource))" if analysis.per == "person" else " (one row per account)"),
        f"- subject: {', '.join(f'{k}={v}' for k, v in analysis.subject.items())}",
    ]
    if analysis.conditions:
        lines.append(f"- conditions: {', '.join(analysis.conditions)}")
    if analysis.days is not None:
        lines.append(f"- threshold: {analysis.days} days (put it in a module constant)")
    if analysis.resource_type:
        lines.append(f"- RESOURCE_TYPE: {analysis.resource_type}")
    if analysis.fields_needed:
        lines.append(f"- fields to read: {', '.join(analysis.fields_needed)}")
    lines.append(f"- REQUIRES = {analysis.requires!r}")
    for note in analysis.notes:
        lines.append(f"- note: {note}")
    return "\n".join(lines)


# -- REQUIRES and scope guards on a draft -----------------------------------------

_REQUIRES_RE = re.compile(r"^REQUIRES\s*=\s*\[(?P<body>[^\]]*)\]", re.MULTILINE)
_RESOURCE_TYPE_LINE_RE = re.compile(r"^RESOURCE_TYPE\s*=.*$", re.MULTILINE)


def declared_requires(source_text: str) -> list[str]:
    match = _REQUIRES_RE.search(source_text)
    if not match:
        return []
    return re.findall(r"""["']([^"']+)["']""", match.group("body"))


def ensure_requires(source_text: str, keys: list[str] | tuple[str, ...]) -> str:
    """``source_text`` declaring every key in ``keys`` in ``REQUIRES``.

    Inserted after the ``RESOURCE_TYPE`` line when the draft has none, merged
    when it has some. A draft the model wrote without ``REQUIRES`` would
    otherwise report as assessable on a tenant whose connector never collects
    the field it reads.
    """
    wanted = [key for key in keys if key]
    if not wanted:
        return source_text
    existing = declared_requires(source_text)
    merged = list(existing) + [key for key in wanted if key not in existing]
    if existing == merged:
        return source_text
    literal = "REQUIRES = [" + ", ".join(f'"{key}"' for key in merged) + "]"
    if _REQUIRES_RE.search(source_text):
        return _REQUIRES_RE.sub(literal, source_text, count=1)
    match = _RESOURCE_TYPE_LINE_RE.search(source_text)
    if match is None:
        return source_text
    end = match.end()
    return source_text[:end] + "\n" + literal + source_text[end:]


_SINGLE_APP_GUARD_RE = re.compile(
    r"""application\.get\(\s*["']type["']\s*\)\s*(!=|not in)\s*|if not application_matches\(""",
)


def single_app_guard(source_text: str) -> str | None:
    """The line where a draft early-returns on the application type, or None.

    A cross-application policy must evaluate every application; this is the
    guard the single-app idiom teaches, and models carry it over."""
    for line in source_text.splitlines():
        if _SINGLE_APP_GUARD_RE.search(line):
            return line.strip()
    return None
