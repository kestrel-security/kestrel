# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""AI drafts must use only the names the sandbox provides.

An LLM draft for "Okta contractors who haven't signed in for 30 days" used
``datetime.now() - timedelta(days=30)``. It compiled, passed its fixture test
(the only matching row returned before the datetime line), and then raised
NameError in dry run. The prompt now lists the available globals, and
Validate reports an unknown name before anything runs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from kestrel.connectors.sdk.base import RawObject
from kestrel.policies import generate
from kestrel.policies.authoring import parse_policy_source
from kestrel.policies.generate_catalog import INTENT_TEMPLATES, few_shot_for_connector
from kestrel.policies.llm_settings import LlmCredentials
from kestrel.policies.packs import get_packs_dir
from kestrel.policies.runtime import compile_and_validate
from kestrel.policies.runtime.helpers import POLICY_HELPERS
from kestrel.policies.runtime.restricted import RestrictedPythonRuntime, _policy_safe_builtins
from kestrel_connector_okta.normalizer import OktaNormalizer

_REPO = Path(__file__).resolve().parents[3]
_OKTA_USERS = _REPO / "connectors" / "okta" / "fixtures" / "users.json"

DEMO_INTENT = (
    "Flag Okta contractors or external users who are still active but haven't signed in for 30 days, or have never signed in"
)

_HEADER = """POLICY_ID = "okta-stale-external-users"
TITLE = "Okta external users inactive for 30+ days"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Active Okta contractors or external users with no sign-in in 30 days."
REMEDIATION = "Confirm the engagement is ongoing or deactivate the account."
"""

_EVIDENCE = """

def evidence(resource):
    identity = resource.get("identity") or {}
    return {"identity.email": identity.get("email"), "identity.last_active_at": identity.get("last_active_at")}
"""

# The draft from the bug report: no application filter, datetime/timedelta.
BROKEN_DRAFT = (
    _HEADER
    + """

def policy(resource):
    identity = resource.get("identity") or {}
    if identity.get("is_disabled"):
        return True
    if not identity.get("is_external"):
        return True
    last_active_at = identity.get("last_active_at")
    if last_active_at is None:
        return False
    thirty_days_ago = datetime.now() - timedelta(days=30)
    return last_active_at >= thirty_days_ago
"""
    + _EVIDENCE
)

CORRECTED_DRAFT = (
    _HEADER
    + """

def policy(resource):
    application = resource.get("application") or {}
    identity = resource.get("identity") or {}
    if application.get("type") != "okta":
        return True
    if identity.get("is_disabled"):
        return True
    if not identity.get("is_external"):
        return True
    return within_last_days(identity.get("last_active_at"), 30)
"""
    + _EVIDENCE
)


def _errors(source: str) -> list[str]:
    return [err.message for err in parse_policy_source(source).errors]


def _policy(body: str) -> str:
    return _HEADER + "\n" + body + _EVIDENCE


# -- prompt ------------------------------------------------------------------


@pytest.mark.parametrize("connector_hint", ["okta", None])
def test_system_prompt_lists_every_policy_global(connector_hint: str | None) -> None:
    prompt = generate._system_prompt(resource_type="identity", connector_hint=connector_hint)
    for name in [*POLICY_HELPERS, "time"]:
        assert f"- {name}" in prompt, name
    assert "datetime, timedelta, re, json and every other module are unavailable" in prompt
    assert "within_last_days" in prompt
    assert "not recent" in prompt
    assert 'application.get("type") !=' in prompt


def test_repair_prompt_carries_the_same_rules() -> None:
    for name in POLICY_HELPERS:
        assert f"- {name}" in generate._REPAIR_SYSTEM, name
    assert "__POLICY_RULES__" not in generate._REPAIR_SYSTEM
    assert "__POLICY_RULES__" not in generate._LLM_SYSTEM


def test_prompt_descriptions_come_from_helper_docstrings() -> None:
    prompt = generate._system_prompt(resource_type=None, connector_hint=None)
    assert "within_last_days(value, days): True when value is a timestamp no more than days days ago." in prompt
    assert "days_since(value): Days elapsed since value, or None if it is missing." in prompt


def test_prompt_names_exactly_the_builtins_the_sandbox_has() -> None:
    listed = generate._POLICY_RULES.split("- Safe builtins:", 1)[1].split("\n", 1)[0]
    names = [name.strip(" .") for name in listed.split(",") if name.strip(" .")]
    expected = sorted(n for n in _policy_safe_builtins() if n[0].islower())
    assert names == expected


@pytest.mark.parametrize("resource_type", [None, "identity", "tenant_setting", "event"])
def test_few_shot_examples_pass_validation(resource_type: str | None) -> None:
    assert _errors(few_shot_for_connector("okta", resource_type)) == []


def test_intent_templates_pass_validation() -> None:
    for template in INTENT_TEMPLATES:
        assert _errors(template.source_factory("Example intent")) == [], template.name


# -- static name check -------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "name"),
    [
        ("def policy(resource):\n    return datetime.now().year > 2000\n", "datetime"),
        ("def policy(resource):\n    window = timedelta(days=30)\n    return bool(window)\n", "timedelta"),
        ("def policy(resource):\n    return is_stale(resource)\n", "is_stale"),
    ],
)
def test_unknown_names_fail_validation(body: str, name: str) -> None:
    parsed = parse_policy_source(_policy(body))
    assert not parsed.is_valid
    (error,) = parsed.errors
    assert error.message.startswith(f"Unknown name {name!r}.")
    assert error.line is not None
    assert error.column is not None


def test_time_like_names_point_at_the_helpers() -> None:
    (message,) = _errors(_policy("def policy(resource):\n    return datetime.now().year > 2000\n"))
    assert message == (
        "Unknown name 'datetime'. Policies cannot import; use now / within_last_days / days_since for time checks."
    )


def test_a_misspelled_helper_gets_a_suggestion() -> None:
    (message,) = _errors(_policy("def policy(resource):\n    return within_last_day(None, 3)\n"))
    assert message == "Unknown name 'within_last_day'. Did you mean 'within_last_days'?"


def test_known_names_pass_validation() -> None:
    body = """
WINDOW_DAYS = 30
SKIP = frozenset({"bot"})


def label_of(identity):
    return (identity.get("email") or "").lower()


def is_recent(value, days=WINDOW_DAYS):
    return within_last_days(value, days)


def policy(resource):
    identity = resource.get("identity") or {}
    age = days_since(identity.get("created_at_source"))
    now = time.time()
    names = [role.lower() for role in resource.get("roles") or []]
    pick = lambda xs: [x for x in xs if x not in SKIP]
    try:
        parsed = parse_timestamp(identity.get("last_active_at"))
    except PolicyDataError as exc:
        return bool(exc)
    if age is not None and age < 1 and now > 0 and parsed is None:
        return True
    if has_admin_grant(resource) or application_matches(resource, ("okta",), None):
        return is_recent(identity.get("last_active_at")) and bool(pick(names)) and bool(label_of(identity))
    return isinstance(age, (int, float)) and len(sorted(names)) >= 0
"""
    assert _errors(_policy(body)) == []


def test_reports_each_unknown_name_once_in_source_order() -> None:
    body = (
        "def policy(resource):\n"
        "    a = timedelta(days=1)\n"
        "    b = datetime.now()\n"
        "    c = datetime.now()\n"
        "    return bool(a and b and c)\n"
    )
    parsed = parse_policy_source(_policy(body))
    assert [e.message.split(".")[0] for e in parsed.errors] == ["Unknown name 'timedelta'", "Unknown name 'datetime'"]
    assert parsed.errors[0].line < parsed.errors[1].line


def test_every_pack_policy_passes_validation() -> None:
    paths = sorted(get_packs_dir().glob("*/policies/*.py"))
    assert paths
    failures = {str(p.relative_to(get_packs_dir())): _errors(p.read_text()) for p in paths}
    assert {path: errs for path, errs in failures.items() if errs} == {}


def test_runtime_compile_is_unchanged() -> None:
    # The check is authoring-only: stored and shipped policies load as before.
    assert compile_and_validate(BROKEN_DRAFT).contract.policy_id == "okta-stale-external-users"


# -- regression: the demo intent ----------------------------------------------


def _okta_demo_rows() -> list[dict[str, Any]]:
    """Identity rows for the bundled Okta demo users, plus external identities
    in other apps that an unscoped policy would wrongly flag."""
    normalizer = OktaNormalizer()
    rows: list[dict[str, Any]] = []
    for user in json.loads(_OKTA_USERS.read_text()):
        raw = RawObject(object_type="user", provider_id=user["id"], payload=user, collected_at=datetime.now(UTC))
        (identity,) = normalizer.normalize("user", raw)
        rows.append(
            {
                "_subject_type": "identity",
                "_subject_id": identity.attributes["email"],
                "identity": dict(identity.attributes),
                "application": {"type": "okta", "name": "Okta"},
                "roles": [],
            }
        )
    for app in ("github", "slack", "google_workspace"):
        rows.append(
            {
                "_subject_type": "identity",
                "_subject_id": f"guest@{app}",
                "identity": {
                    "email": f"guest@{app}.example",
                    "is_external": True,
                    "is_disabled": False,
                    "last_active_at": None,
                },
                "application": {"type": app, "name": app},
                "roles": [],
            }
        )
    return rows


def test_broken_demo_draft_fails_validate_with_a_clear_message() -> None:
    parsed = parse_policy_source(BROKEN_DRAFT)
    assert not parsed.is_valid
    messages = [str(err) for err in parsed.errors]
    assert any("Unknown name 'datetime'" in m and "within_last_days / days_since" in m for m in messages), messages
    assert any("Unknown name 'timedelta'" in m for m in messages), messages


def test_broken_demo_draft_really_fails_at_runtime() -> None:
    # What Validate now prevents: NameError on the first stale external row.
    compiled = compile_and_validate(BROKEN_DRAFT)
    stale = {"identity": {"is_external": True, "last_active_at": datetime(2026, 1, 1, tzinfo=UTC)}}
    with pytest.raises(NameError, match="datetime"):
        compiled.policy_fn(stale)


def test_corrected_demo_draft_flags_only_the_active_okta_contractor() -> None:
    assert parse_policy_source(CORRECTED_DRAFT).is_valid
    rows = _okta_demo_rows()
    matched = RestrictedPythonRuntime().match_rows(compile_and_validate(CORRECTED_DRAFT), rows)
    assert [rows[i]["_subject_id"] for i in matched] == ["contractor@vendor.example.com"]


# -- repair loop ---------------------------------------------------------------


def test_generate_repairs_a_draft_that_uses_datetime(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[dict[str, str]]] = []

    def fake_chat(*, messages: list[dict[str, str]], **_: Any) -> str:
        calls.append(messages)
        return BROKEN_DRAFT if len(calls) == 1 else CORRECTED_DRAFT

    monkeypatch.setattr(generate, "chat_completion", fake_chat)
    creds = LlmCredentials(api_key="k", provider="openai", model="m", base_url="http://llm.invalid", source="env")
    draft = generate.generate_policy_draft(intent=DEMO_INTENT, connector_hint="okta", credentials=creds)

    assert len(calls) == 2, "expected one draft and one repair turn"
    repair_user = calls[1][-1]["content"]
    assert "Unknown name 'datetime'" in repair_user
    assert draft["source_text"] == CORRECTED_DRAFT
    assert draft["validation"]["valid"] is True
