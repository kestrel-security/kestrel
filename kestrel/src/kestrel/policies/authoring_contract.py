# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""What a policy author (human or AI) may use, in one place.

The generate prompt, ``kestrel policy contract``, ``GET
/api/v1/policies/authoring-contract`` and the helper table in
``docs/policies.md`` all read from here, and every list is derived from the
sandbox itself (``POLICY_HELPERS``, the safe builtins, the policy ``time``
subset), so what an agent is told cannot drift from what the runtime provides.
Each idiom names a shipped pack policy that uses it; a unit test keeps the two
in step.
"""

from __future__ import annotations

import functools
import inspect
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from kestrel.policies.packs import get_packs_dir
from kestrel.policies.resource_schemas import RESOURCE_SCHEMAS
from kestrel.policies.runtime.helpers import POLICY_HELPERS, POLICY_TIME
from kestrel.policies.runtime.restricted import _policy_safe_builtins

CONTRACT_VERSION = 3

RULES: tuple[str, ...] = (
    "Define POLICY_ID, TITLE, SEVERITY, RESOURCE_TYPE, DESCRIPTION, REMEDIATION, policy(resource) "
    "and evidence(resource). policy() returns True when compliant and False to open a finding.",
    "policy() answers 'is this row compliant?', not 'should this row be flagged?'. Every row the intent "
    'asks to flag must reach `return False`; e.g. for "flag users who never signed in", a missing '
    "last_active_at returns False, never True.",
    "There are no imports. datetime, timedelta, re, json and every other module are unavailable; "
    "only the names listed here exist.",
    "The module body may only define constants (literals) and functions. Put all logic inside policy().",
    "Use now / within_last_days / days_since / parse_timestamp for every time check. Never compare "
    "row timestamps directly: they may be ISO strings, naive datetimes, or timezone-aware datetimes.",
    'within_last_days treats a missing timestamp as "not recent", so '
    '`return within_last_days(identity.get("last_active_at"), 30)` flags both stale and never-active '
    "accounts. Check for None first if absence should mean compliant.",
    'Use duration_seconds for ISO 8601 (P30D, PT12H) and protobuf ("86400s") durations.',
    "A single-application policy returns True early for rows from other applications: "
    '`if application.get("type") != "okta": return True`. Use application_matches only to scope '
    "custom connectors by name.",
    "A cross-application policy (contractors in any app, a person disabled in the identity provider, admin "
    "in two apps) runs once per account in every application and must NOT early-return on "
    "application.type. Skip bots by identity_type and, when the identity provider's own account is the "
    'correct end state, rows whose application.type is in cluster["idp_application_types"].',
    "Report a finding on the account an operator must act on (the surviving or privileged account), "
    "never on the identity-provider account that is already disabled. For a per-person check gate with "
    "`if not is_representative(resource): return True` so one person is one finding.",
    "worker_type comes from the provider's profile and operator classification rules and may be 'unknown'. "
    "Use worker_type_of(resource); decide what unknown means (usually: not shown to be a contractor, "
    "return True) and say so in DESCRIPTION. is_external is the application's guest flag, not 'contractor'.",
    "Only last_active_source login, audit and analytics are activity; profile is not, and GitHub's audit log "
    "sees only administrative actions. Use activity_status(resource, DAYS) and treat 'unknown' as not "
    "assessable (return True), 'never' like stale.",
    "Set REQUIRES to the identity:* capability keys the policy reads (identity:last_sign_in, "
    "identity:worker_type, identity:groups, identity:disabled_at, identity:expires_at, identity:oauth_grants).",
    "Comprehensions and lambdas are fine inside functions; only the module body is restricted to constants and def.",
    "Treat only an explicit False as a violation for tri-state flags such as mfa_enabled: None means "
    "the connector could not read it.",
    'Read nested fields with .get() and `or {}`, or with get_path(resource, "a.b.c").',
    "On data you cannot interpret, raise PolicyDataError. Never catch Exception: a guessed answer hides findings.",
    "No I/O, no exec/eval/open, no global/nonlocal. Never enable the policy; drafts are human-reviewed.",
)


@dataclass(frozen=True)
class Idiom:
    name: str
    when: str
    snippet: str
    example: str  # a pack policy, relative to the packs directory, that uses the idiom
    uses: str  # text the example must contain (checked by a unit test)


IDIOMS: tuple[Idiom, ...] = (
    Idiom(
        name="scope-to-application",
        when="Every policy: skip rows from other connected apps first.",
        snippet='application = resource.get("application") or {}\nif application.get("type") != "okta":\n    return True',
        example="okta-posture/policies/okta_dormant_admin.py",
        uses='application.get("type") != "okta"',
    ),
    Idiom(
        name="dormant-account",
        when="Accounts with no activity in N days, including ones never active.",
        snippet='return within_last_days(identity.get("last_active_at"), DORMANT_DAYS)',
        example="okta-posture/policies/okta_dormant_admin.py",
        uses="return within_last_days(",
    ),
    Idiom(
        name="recent-event",
        when="Audit-log events: only consider events from the last N days.",
        snippet='if not within_last_days(event.get("occurred_at"), 30):\n    return True',
        example="github-posture/policies/github_activity_deploy_key_created.py",
        uses="if not within_last_days(",
    ),
    Idiom(
        name="tenant-setting-key",
        when="Tenant settings: select one setting by key, then judge its value.",
        snippet='setting = resource.get("setting") or {}\nif setting.get("key") != "<setting key>":\n    return True',
        example="github-posture/policies/github_actions_default_token_write.py",
        uses='setting.get("key") !=',
    ),
    Idiom(
        name="per-resource-setting",
        when="Repositories, channels, drives: read the settings that govern one resource.",
        snippet=(
            'setting = (resource.get("settings_by_key") or {}).get("repo_default_branch_protected")\n'
            "if setting is None:\n    return True  # not collected: no evidence either way\n"
            'return setting.get("value") is not False'
        ),
        example="github-posture/policies/github_repo_default_branch_unprotected.py",
        uses="settings_by_key",
    ),
    Idiom(
        name="admin-without-mfa",
        when="Identities holding an admin grant; tri-state MFA flag.",
        snippet='if identity.get("mfa_enabled") is not False:\n    return True\nreturn not has_admin_grant(resource)',
        example="github-posture/policies/github_repo_admin_without_mfa.py",
        uses="has_admin_grant(",
    ),
    Idiom(
        name="duration-setting",
        when="Settings stored as durations (session length, grace periods).",
        snippet='return (duration_seconds(value.get("sessionLength")) or 0) / 3600 <= MAX_SESSION_HOURS',
        example="gws-posture/policies/gws_session_too_long.py",
        uses="duration_seconds(",
    ),
    Idiom(
        name="cross-app-skip-non-human",
        when="Cross-application policies: skip bots, never skip by application.type.",
        snippet=(
            'HUMAN_IDENTITY_TYPES = ("user",)\n'
            'if identity.get("identity_type") not in HUMAN_IDENTITY_TYPES:\n    return True'
        ),
        example="cross-app/policies/cross_app_departed_still_has_access.py",
        uses='identity.get("identity_type") not in HUMAN_IDENTITY_TYPES',
    ),
    Idiom(
        name="report-on-surviving-account",
        when="The identity provider disabled the person: report the account still enabled elsewhere.",
        snippet=(
            'cluster = resource.get("cluster") or {}\n'
            'if application.get("type") in (cluster.get("idp_application_types") or []):\n'
            "    return True  # the IdP account being disabled is the correct end state\n"
            'return cluster.get("idp_status") != "disabled"'
        ),
        example="cross-app/policies/cross_app_departed_still_has_access.py",
        uses='cluster.get("idp_status") != "disabled"',
    ),
    Idiom(
        name="one-finding-per-person",
        when="A check about the person (admin in two apps, dormant everywhere): one finding, not one per account.",
        snippet="if not is_representative(resource):\n    return True",
        example="cross-app/policies/cross_app_privileged_concentration.py",
        uses="is_representative(",
    ),
    Idiom(
        name="other-accounts-of-person",
        when="Look at the same person's other enabled accounts.",
        snippet=(
            "elsewhere = cluster_accounts(resource, include_self=False, active_only=True)\n"
            "return not any(has_privileged_role(a) for a in elsewhere)"
        ),
        example="cross-app/policies/cross_app_group_scoped_privilege.py",
        uses="cluster_accounts(resource, include_self=False, active_only=True)",
    ),
    Idiom(
        name="worker-type",
        when="Contractors, vendors, guests: read the person's classification, and decide what unknown means.",
        snippet=(
            'CONTINGENT_WORKER_TYPES = ("contractor", "vendor_or_partner")\n'
            "if worker_type_of(resource) not in CONTINGENT_WORKER_TYPES:\n"
            "    return True  # unknown is not shown to be a contractor"
        ),
        example="cross-app/policies/cross_app_contractor_dormant_in_app.py",
        uses="worker_type_of(resource) not in CONTINGENT_WORKER_TYPES",
    ),
    Idiom(
        name="trusted-activity",
        when="Dormancy on any application: only trusted sources count, unknown is not assessable.",
        snippet=(
            "status = activity_status(resource, STALE_DAYS)\n"
            'if status == "unknown":\n    return True\n'
            'return status == "active"'
        ),
        example="cross-app/policies/cross_app_contractor_dormant_in_app.py",
        uses="activity_status(resource, STALE_DAYS)",
    ),
    Idiom(
        name="idp-account-state",
        when="Compare an account to the person's identity-provider account (MFA, disabled, disabled_at).",
        snippet=(
            "idp = idp_account(resource)\n"
            'if idp is None or idp.get("is_disabled"):\n    return True\n'
            'if idp.get("mfa_enabled") is not False:\n    return True'
        ),
        example="cross-app/policies/cross_app_admin_without_idp_mfa.py",
        uses="idp = idp_account(resource)",
    ),
)

#: Endpoints an outside agent uses to check a draft, in order.
WORKFLOW: tuple[dict[str, str], ...] = (
    {"step": "validate", "api": "POST /api/v1/policies/validate", "cli": "kestrel policy validate <file>"},
    {
        "step": "fixture test",
        "api": "POST /api/v1/policies/test-draft",
        "cli": "kestrel policy test <file> --fixtures <json>",
    },
    {"step": "dry run", "api": "POST /api/v1/policies/dry-run-draft", "cli": ""},
)


def _signature(name: str, value: Any) -> str:
    if not inspect.isfunction(value):
        return name
    params = [p.replace(annotation=inspect.Parameter.empty) for p in inspect.signature(value).parameters.values()]
    return f"{name}({', '.join(str(p) for p in params)})"


def _summary(value: Any) -> str:
    """First paragraph of the docstring, on one line, without RST markup."""
    first = (inspect.getdoc(value) or "").split("\n\n", 1)[0]
    return " ".join(first.replace("``", "").split())


def helper_entries() -> list[dict[str, str]]:
    return [
        {"name": name, "signature": _signature(name, value), "summary": _summary(value), "doc": inspect.getdoc(value) or ""}
        for name, value in POLICY_HELPERS.items()
    ]


def sandbox_builtins() -> dict[str, list[str]]:
    names = sorted(name for name in _policy_safe_builtins() if not name.startswith("_"))
    exceptions = [n for n in names if n[0].isupper() and n not in ("True", "False", "None", "Ellipsis")]
    return {
        "functions": [n for n in names if n[0].islower()],
        "exceptions": exceptions,
        "constants": [n for n in names if n in ("True", "False", "None")],
    }


def time_attributes() -> list[str]:
    return sorted(name for name in vars(POLICY_TIME) if not name.startswith("_"))


_RESOURCE_TYPE_RE = re.compile(r"^RESOURCE_TYPE\s*=\s*[\"']([a-z_]+)[\"']", re.MULTILINE)
#: application.type -> the pack holding that connector's reviewed policies
#: (``cross_app`` -> the cross-app pack).
_CONNECTOR_PACKS = {
    "okta": "okta-posture",
    "github": "github-posture",
    "google_workspace": "gws-posture",
    "slack": "slack-posture",
    "cross_app": "cross-app",
}


def _strip_header(source: str) -> str:
    lines = source.splitlines()
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    return "\n".join(lines).strip() + "\n"


@functools.lru_cache(maxsize=64)
def _pack_examples_cached(packs_dir: Path, connector: str, resource_type: str | None, limit: int) -> tuple[str, ...]:
    pack = _CONNECTOR_PACKS.get(connector)
    if pack is None or limit < 1:
        return ()
    candidates: list[tuple[bool, int, str, str]] = []
    for path in sorted((packs_dir / pack / "policies").glob("*.py")):
        try:
            source = _strip_header(path.read_text())
        except OSError:
            continue
        match = _RESOURCE_TYPE_RE.search(source)
        if resource_type and (match is None or match.group(1) != resource_type):
            continue
        uses_helper = any(f"{name}(" in source for name in POLICY_HELPERS)
        # Prefer short policies that show a shared helper in use.
        candidates.append((not uses_helper, source.count("\n"), path.name, source))
    return tuple(source for *_, source in sorted(candidates)[:limit])


def pack_examples(connector: str | None, resource_type: str | None, limit: int = 2) -> list[str]:
    """Up to ``limit`` shipped pack policies for ``connector`` (an
    ``application.type``) and ``resource_type``, licence header removed.
    Empty when the packs directory is not present."""
    if not connector:
        return []
    return list(_pack_examples_cached(get_packs_dir(), connector, resource_type, limit))


def policy_authoring_contract() -> dict[str, Any]:
    """The full contract as JSON-safe data."""
    return {
        "version": CONTRACT_VERSION,
        "rules": list(RULES),
        "helpers": helper_entries(),
        "time": {
            "attributes": time_attributes(),
            "note": "time.time() and time.time_ns() read the evaluation clock, fixed for the run like now().",
        },
        "builtins": sandbox_builtins(),
        "resource_schemas": dict(RESOURCE_SCHEMAS),
        "idioms": [asdict(idiom) for idiom in IDIOMS],
        "workflow": list(WORKFLOW),
    }


def render_prompt_rules() -> str:
    """The contract as prompt text for the generate and repair turns."""
    builtins = sandbox_builtins()
    lines = [
        "Names available as globals (nothing else exists; there are no imports):",
        *(f"- {entry['signature']}: {entry['summary']}" for entry in helper_entries()),
        f"- time: a subset of the time module ({', '.join(time_attributes())}); prefer now().",
        f"- Safe builtins: {', '.join(builtins['functions'])}.",
        "- Exception classes such as ValueError, KeyError and TypeError.",
        "",
        "Rules:",
        *(f"- {rule}" for rule in RULES),
        "",
        "Idioms (from shipped pack policies):",
    ]
    for idiom in IDIOMS:
        lines.append(f"# {idiom.name}: {idiom.when}")
        lines.append(idiom.snippet)
    return "\n".join(lines)


def render_markdown() -> str:
    """The contract as a Markdown document for agents and humans."""
    builtins = sandbox_builtins()
    out = [
        f"# Kestrel policy authoring contract (v{CONTRACT_VERSION})",
        "",
        "Generated from the policy sandbox; `kestrel policy contract` and "
        "`GET /api/v1/policies/authoring-contract` return the same content.",
        "",
        "## Rules",
        "",
        *(f"- {rule}" for rule in RULES),
        "",
        "## Helpers",
        "",
    ]
    for entry in helper_entries():
        out += [f"### `{entry['signature']}`", "", entry["doc"], ""]
    out += [
        "## Other globals",
        "",
        f"- `time`: {', '.join(f'`{a}`' for a in time_attributes())}. "
        "`time.time()` reads the same fixed evaluation clock as `now()`.",
        f"- Builtins: {', '.join(f'`{n}`' for n in builtins['functions'])}.",
        f"- Exceptions: {', '.join(f'`{n}`' for n in builtins['exceptions'])}.",
        "",
        "## Idioms",
        "",
    ]
    for idiom in IDIOMS:
        out += [
            f"### {idiom.name}",
            "",
            idiom.when,
            "",
            "```python",
            idiom.snippet,
            "```",
            "",
            f"Example: `packs/{idiom.example}`",
            "",
        ]
    out += ["## Resource row shapes", ""]
    for name, schema in RESOURCE_SCHEMAS.items():
        out += [f"### `{name}`", "", "```text", schema, "```", ""]
    out += ["## Checking a draft", "", "| Step | API | CLI |", "|---|---|---|"]
    for step in WORKFLOW:
        out.append(f"| {step['step']} | `{step['api']}` | {f'`{step["cli"]}`' if step['cli'] else '—'} |")
    return "\n".join(out).rstrip() + "\n"
