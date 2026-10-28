# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""AI-assisted Python policy draft generation (draft only; never auto-enables)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from typing import Any

import httpx
from sqlalchemy.orm import Session

from kestrel.db.models.llm_settings import PROVIDER_ANTHROPIC, PROVIDER_OPENAI
from kestrel.policies.authoring import parse_policy_source
from kestrel.policies.authoring_contract import pack_examples, render_prompt_rules
from kestrel.policies.generate_catalog import (
    connector_catalog_for_prompt,
    fixtures_for_intent,
    match_intent_template,
    normalize_connector_hint,
)
from kestrel.policies.generate_context import resolve_connector_hint
from kestrel.policies.generate_intent import (
    CROSS_APP_CONNECTOR,
    SCOPE_CROSS_APP,
    IntentAnalysis,
    analyze_intent,
    ensure_requires,
    render_plan,
    single_app_guard,
)
from kestrel.policies.llm_settings import (
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_MODEL,
    LlmCredentials,
    resolve_llm_credentials,
)
from kestrel.policies.probes import probe_policy
from kestrel.policies.resource_schemas import FIXTURE_DEMOS, fixture_demo_for, schema_docs_for_prompt
from kestrel.policies.testing import run_fixture_test_dict

logger = logging.getLogger(__name__)

# Use replace() for schema injection — prompts contain literal `{...}` JSON examples.
_LLM_SYSTEM = """You write Kestrel Python security policies for SaaS configuration posture and audit-log events.

Return ONLY valid Python source (no markdown fences) defining:
- POLICY_ID (kebab-case slug string)
- TITLE, SEVERITY (low|medium|high|critical), RESOURCE_TYPE
  (identity | grant | tenant_setting | event | resource | application)
- DESCRIPTION, REMEDIATION
- Optional COMPLIANCE = {"framework": ["control"]}

def policy(resource):
    # resource is a dataload dict for RESOURCE_TYPE (see schema below).
    # Return True if compliant; False to open a finding.

def evidence(resource):
    # Return a flat dict of evidence field paths -> values.

__POLICY_RULES__

Match existing pack style. Never enable the policy — this is a human-reviewed draft only.

__SCHEMAS__

__CONNECTOR_CATALOG__

__PACK_EXAMPLES__
"""

_REPAIR_SYSTEM = """You repair Kestrel Python security policies that failed validation or fixture tests.

Return ONLY corrected valid Python source (no markdown fences). Keep the same intent.
The policy must define POLICY_ID, TITLE, SEVERITY, RESOURCE_TYPE, DESCRIPTION, REMEDIATION,
policy(resource), and evidence(resource).
Return True from policy() when compliant; False to open a finding.

__POLICY_RULES__

__SCHEMAS__

__CONNECTOR_CATALOG__
"""


# What a policy may call, built from the sandbox by authoring_contract so it
# cannot drift. Without this list models reach for ``datetime``, which compiles
# and then raises NameError on the first row that reaches it.
_POLICY_RULES = render_prompt_rules()
_LLM_SYSTEM = _LLM_SYSTEM.replace("__POLICY_RULES__", _POLICY_RULES)
_REPAIR_SYSTEM = _REPAIR_SYSTEM.replace("__POLICY_RULES__", _POLICY_RULES)

_TEMPLATE_PROVIDER = "template"
_UNCONFIGURED_PROVIDER = "unconfigured"
_ERROR_PROVIDER = "error"

_UNCONFIGURED_MESSAGE = (
    "AI is not configured. Set up Settings → AI (Admin) or KESTREL_LLM_API_KEY, "
    "or use a supported intent chip (Okta admins without MFA, contractors dormant in an app, "
    "accounts that outlived offboarding)."
)
#: Repair turns after the first draft. Two: the first repair fixes what the
#: checks named, the second catches a repair that broke something else.
_MAX_REPAIR_TURNS = 2

_RESOURCE_TYPE_RE = re.compile(r"^RESOURCE_TYPE\s*=\s*[\"']([a-z_]+)[\"']", re.MULTILINE)
_MAX_LLM_RETRIES = 2
_RETRYABLE_HTTP_STATUS = frozenset({429, 502, 503, 504})
_MAX_RETRY_DELAY_SECONDS = 4.0
_QUOTA_CODES = frozenset({"insufficient_quota", "credit_balance_exhausted"})
_RATE_LIMIT_CODES = frozenset(
    {"rate_limit_exceeded", "rate_limit_error", "overloaded_error", "insufficient_quota", "credit_balance_exhausted"}
)


def _slug_from_intent(intent: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", intent.lower().strip())[:48].strip("-")
    if not cleaned:
        cleaned = "custom-draft"
    digest = hashlib.sha256(intent.encode("utf-8")).hexdigest()[:8]
    return f"{cleaned}-{digest}"[:64].strip("-")


def _extract_assistant_source(content: str) -> str:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _validation_payload(source_text: str) -> dict[str, Any]:
    """Compile with RestrictedPython and return ``{valid, errors, slug}``."""
    if not source_text.strip():
        return {"valid": False, "errors": [], "slug": None}
    parsed = parse_policy_source(source_text)
    slug: str | None = None
    if parsed.compiled is not None:
        slug = parsed.compiled.contract.policy_id
    return {
        "valid": parsed.is_valid,
        "errors": [str(err) for err in parsed.errors],
        "slug": slug,
    }


def _resource_type_from_source(source_text: str) -> str | None:
    match = _RESOURCE_TYPE_RE.search(source_text)
    if match and match.group(1) in FIXTURE_DEMOS:
        return match.group(1)
    return None


def _fixture_test_payload(source_text: str, fixtures: dict[str, Any] | None) -> dict[str, Any] | None:
    if not fixtures or not source_text.strip():
        return None
    try:
        result = run_fixture_test_dict(source_text, fixtures)
    except ValueError as exc:
        return {
            "passed": False,
            "expected": list(fixtures.get("expected_match_subject_ids", [])),
            "actual": [],
            "error": str(exc),
        }
    return {
        "passed": result.passed,
        "expected": sorted(result.expected_subject_ids),
        "actual": sorted(result.actual_subject_ids),
        "missing": sorted(result.missing),
        "unexpected": sorted(result.unexpected),
    }


def scaffold_fixtures(
    *,
    resource_type: str | None = None,
    source_text: str | None = None,
    connector_hint: str | None = None,
    template: Any = None,
) -> dict[str, Any]:
    """Minimal match + non-match fixture pair aligned with connector demos."""
    if template is not None:
        return dict(template.fixtures)

    rt = resource_type if resource_type in FIXTURE_DEMOS else None
    if rt is None and source_text:
        rt = _resource_type_from_source(source_text)
    raw = fixture_demo_for(rt, connector_hint=normalize_connector_hint(connector_hint))
    data = json.loads(raw)
    if not isinstance(data, dict) or "rows" not in data:
        raise ValueError("fixture scaffold produced unexpected shape")
    return data


def _provider_error_code(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:  # not JSON (JSONDecodeError and UnicodeDecodeError are both ValueErrors)
        return ""
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code") or error.get("type")
        if code:
            return str(code)
    err_type = payload.get("type")
    return str(err_type) if err_type else ""


def _provider_error_message(response: httpx.Response) -> str:
    """The provider's own explanation of a failure, for the server log only."""
    try:
        payload = response.json()
    except ValueError:
        return ""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])[:500]
    return ""


def operator_llm_error_message(exc: BaseException) -> str:
    """Operator-facing LLM failure — never leak provider URLs or raw httpx text."""
    if isinstance(exc, httpx.TimeoutException):
        return "AI provider timed out. Try again."
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        code = _provider_error_code(exc.response)
        if status == 429 or code in _RATE_LIMIT_CODES:
            if code in _QUOTA_CODES:
                return (
                    "AI provider quota exceeded. Check billing in Settings → AI, "
                    "or generate from a known Okta intent chip (works offline)."
                )
            return (
                "AI provider is rate-limited. Wait a moment and try again, "
                "or generate from a known Okta intent chip (works offline)."
            )
        if status in (401, 403):
            return "AI provider rejected the API key. Check Settings → AI."
        if status >= 500:
            return "AI provider is unavailable. Try again in a moment."
        return f"AI generation failed (HTTP {status})."
    if isinstance(exc, httpx.RequestError):
        return "Could not reach the AI provider. Check Settings → AI and network access."
    return f"AI generation failed: {exc}"


def _retry_delay_seconds(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("Retry-After", "")
    if header.isdigit():
        return min(float(header), _MAX_RETRY_DELAY_SECONDS)
    return min(0.5 * (2**attempt), _MAX_RETRY_DELAY_SECONDS)


def _post_llm(
    url: str,
    *,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: float = 60.0,
) -> httpx.Response:
    with httpx.Client(timeout=timeout) as client:
        for attempt in range(_MAX_LLM_RETRIES + 1):
            response = client.post(url, headers=headers, json=payload)
            if response.status_code in _RETRYABLE_HTTP_STATUS and attempt < _MAX_LLM_RETRIES:
                delay = _retry_delay_seconds(response, attempt)
                logger.info(
                    "LLM provider returned %s; retrying in %.1fs (attempt %s/%s)",
                    response.status_code,
                    delay,
                    attempt + 1,
                    _MAX_LLM_RETRIES,
                )
                time.sleep(delay)
                continue
            response.raise_for_status()
            return response
    raise RuntimeError("LLM request retries exhausted")  # pragma: no cover


def _pack_examples_block(connector: str | None, resource_type: str | None) -> str:
    """Reviewed pack policies for this connector, so drafts copy shipped style."""
    examples = pack_examples(connector, resource_type)
    if not examples:
        return ""
    heading = (
        "Shipped cross-application policies (match their style)"
        if connector == CROSS_APP_CONNECTOR
        else "Shipped pack policies for this connector (match their style)"
    )
    return heading + ":\n\n" + "\n\n".join(examples)


def _prompt_connectors(connector: str | None, scope: str | None, focus_connector: str | None) -> list[str]:
    """The catalogs a draft needs: the cross-app one for a cross-app scope,
    plus the focus application's (the identity provider, usually)."""
    if scope == SCOPE_CROSS_APP or connector == CROSS_APP_CONNECTOR:
        return [CROSS_APP_CONNECTOR, *([focus_connector] if focus_connector else [])]
    return [connector] if connector else []


def _catalog_block(connector: str | None, resource_type: str | None, scope: str | None, focus: str | None) -> str:
    names = _prompt_connectors(connector, scope, focus)
    blocks = [connector_catalog_for_prompt(name, resource_type) for name in names]
    return "\n\n".join(block for block in blocks if block)


def _system_prompt(
    *,
    resource_type: str | None,
    connector_hint: str | None,
    scope: str | None = None,
    focus_connector: str | None = None,
) -> str:
    connector = normalize_connector_hint(connector_hint)
    catalog = _catalog_block(connector, resource_type, scope, focus_connector)
    system = _LLM_SYSTEM.replace("__SCHEMAS__", schema_docs_for_prompt(resource_type, scope=scope))
    example_connector = CROSS_APP_CONNECTOR if scope == SCOPE_CROSS_APP else connector
    system = system.replace("__PACK_EXAMPLES__", _pack_examples_block(example_connector, resource_type))
    return system.replace("__CONNECTOR_CATALOG__", catalog or "")


def _openai_chat(
    *,
    api_key: str,
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
) -> str:
    response = _post_llm(
        f"{base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        payload={
            "model": model,
            "temperature": temperature,
            "messages": messages,
        },
    )
    content = response.json()["choices"][0]["message"]["content"]
    return _extract_assistant_source(str(content))


def _anthropic_chat(
    *,
    api_key: str,
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
) -> str:
    """Anthropic Messages API — system is a top-level field, not a message role."""
    system_parts: list[str] = []
    chat_messages: list[dict[str, str]] = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            system_parts.append(content)
        else:
            chat_role = "assistant" if role == "assistant" else "user"
            chat_messages.append({"role": chat_role, "content": content})
    if not chat_messages:
        raise ValueError("no user messages for Anthropic chat")

    # No `temperature`: current Claude models reject a non-default sampling
    # value with a 400, and they think before answering, so the output budget
    # covers the reasoning as well as the policy source.
    del temperature
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": 8192,
        "messages": chat_messages,
    }
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)

    response = _post_llm(
        f"{base_url.rstrip('/')}/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        payload=payload,
    )
    body = response.json()
    blocks = body.get("content") or []
    text_parts = [str(block.get("text", "")) for block in blocks if isinstance(block, dict) and block.get("type") == "text"]
    return _extract_assistant_source("\n".join(text_parts))


def chat_completion(
    *,
    api_key: str,
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    provider: str = PROVIDER_OPENAI,
) -> str:
    """Provider-aware chat completion; returns assistant content text."""
    if provider == PROVIDER_ANTHROPIC:
        source_text = _anthropic_chat(
            api_key=api_key,
            base_url=base_url,
            model=model,
            messages=messages,
            temperature=temperature,
        )
    else:
        source_text = _openai_chat(
            api_key=api_key,
            base_url=base_url,
            model=model,
            messages=messages,
            temperature=temperature,
        )
    if not source_text.strip():
        raise ValueError("empty model response")
    return source_text


def _llm_draft(
    *,
    creds: LlmCredentials,
    intent: str,
    resource_type: str | None,
    connector_hint: str | None,
    analysis: IntentAnalysis | None = None,
) -> str:
    user_parts = [f"Intent:\n{intent}"]
    if analysis is not None:
        user_parts.append(render_plan(analysis))
    if resource_type:
        user_parts.append(f"Preferred RESOURCE_TYPE: {resource_type}")
    connector = normalize_connector_hint(connector_hint)
    scope = analysis.scope if analysis else None
    focus = analysis.focus_connector if analysis else None
    if scope == SCOPE_CROSS_APP:
        user_parts.append("Scope: every connected application (cross-application policy reading resource['cluster']).")
    elif connector:
        user_parts.append(f"Connector / app hint: {connector}")
    catalog = _catalog_block(connector, resource_type, scope, focus)
    if catalog:
        user_parts.append(catalog)

    return chat_completion(
        api_key=creds.api_key,
        base_url=creds.base_url,
        model=creds.model,
        provider=creds.provider,
        messages=[
            {
                "role": "system",
                "content": _system_prompt(
                    resource_type=resource_type, connector_hint=connector_hint, scope=scope, focus_connector=focus
                ),
            },
            {"role": "user", "content": "\n\n".join(user_parts)},
        ],
    )


def _fixture_failure_report(fixture_test: dict[str, Any], fixtures: dict[str, Any] | None) -> str:
    """Row by row: what each fixture row should produce and what the draft did.

    "expected [a, b], got [c]" alone does not tell a model *why*; small
    models in particular read policy() as "return True to flag" and repair
    an inverted draft into the same inverted draft.
    """
    expected = set(fixture_test.get("expected") or [])
    actual = set(fixture_test.get("actual") or [])
    lines = ["Fixture test failed. Each row, with what policy() must return:"]
    for row in (fixtures or {}).get("rows") or []:
        subject = str(row.get("_subject_id"))
        want = "False (finding)" if subject in expected else "True (compliant)"
        got = "False (finding)" if subject in actual else "True (compliant)"
        mark = "ok" if (subject in expected) == (subject in actual) else "WRONG"
        data = _compact_row(row)
        lines.append(f"- {subject}: must return {want}, returned {got} [{mark}]  row={json.dumps(data, default=str)}")
    if expected and actual and not expected & actual:
        lines.append(
            "Every row that should open a finding was judged compliant, and the draft flagged rows it should not: "
            "the True/False logic looks inverted. policy() answers 'is this row compliant?': return True when "
            "there is nothing to report and False for the rows the intent asks to flag."
        )
    lines.append('{"$days_ago": n} in a row is a timestamp n days before now.')
    return "\n".join(lines)


def _compact_row(row: dict[str, Any]) -> dict[str, Any]:
    """A fixture row as the repair prompt shows it: the cluster reduced to what
    decides the outcome, the org block dropped."""
    data = {k: v for k, v in row.items() if not k.startswith("_") and k != "org"}
    cluster = data.get("cluster")
    if isinstance(cluster, dict):
        data["cluster"] = {
            "idp_status": cluster.get("idp_status"),
            "worker_type": cluster.get("worker_type"),
            "is_representative": cluster.get("is_representative"),
            "last_active_at": cluster.get("last_active_at"),
            "accounts": [
                {
                    key: account.get(key)
                    for key in (
                        "application_type",
                        "is_disabled",
                        "mfa_enabled",
                        "worker_type",
                        "privileged",
                        "last_active_at",
                        "last_active_source",
                        "disabled_at",
                    )
                }
                for account in cluster.get("accounts") or []
                if isinstance(account, dict)
            ],
        }
    return data


def _repair_draft(
    *,
    creds: LlmCredentials,
    intent: str,
    resource_type: str | None,
    connector_hint: str | None,
    source_text: str,
    errors: list[str],
    fixture_test: dict[str, Any] | None = None,
    fixtures: dict[str, Any] | None = None,
    analysis: IntentAnalysis | None = None,
) -> str:
    """One repair chat turn after validation, probe, fixture-test, or scope failure."""
    error_block = "\n".join(f"- {e}" for e in errors) or "- (unknown error)"
    user = f"Intent:\n{intent}\n\nErrors:\n{error_block}\n\nPrevious source:\n{source_text}"
    if fixture_test and not fixture_test.get("passed") and not fixture_test.get("advisory"):
        user += "\n\n" + _fixture_failure_report(fixture_test, fixtures)
    if analysis is not None:
        user += "\n\n" + render_plan(analysis)
    if resource_type:
        user += f"\n\nPreferred RESOURCE_TYPE: {resource_type}"
    scope = analysis.scope if analysis else None
    focus = analysis.focus_connector if analysis else None
    system = _REPAIR_SYSTEM.replace("__SCHEMAS__", schema_docs_for_prompt(resource_type, scope=scope))
    catalog = _catalog_block(normalize_connector_hint(connector_hint), resource_type, scope, focus)
    system = system.replace("__CONNECTOR_CATALOG__", catalog or "")
    return chat_completion(
        api_key=creds.api_key,
        base_url=creds.base_url,
        model=creds.model,
        provider=creds.provider,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.1,
    )


def _resolve_fixtures(
    *,
    include_fixtures: bool,
    intent: str,
    resource_type: str | None,
    source_text: str,
    connector_hint: str | None,
    template: Any,
    scope: str | None = None,
) -> tuple[dict[str, Any] | None, bool]:
    """Fixtures for the draft, and whether their expected matches fit the intent.

    A template's fixtures, or ones picked for the intent, are authoritative and
    a mismatch triggers repair. Otherwise the generic scaffold's expectations
    were written for another intent: its result is advisory, shown to the
    operator but never used to steer the repair turn.
    """
    if not include_fixtures:
        return None, False
    if template is not None:
        return dict(template.fixtures), True
    rt = resource_type or _resource_type_from_source(source_text)
    matched = fixtures_for_intent(intent, connector_hint=connector_hint, resource_type=rt, scope=scope)
    if matched is not None:
        return json.loads(json.dumps(matched)), True
    scaffold_hint = CROSS_APP_CONNECTOR if scope == SCOPE_CROSS_APP else connector_hint
    return scaffold_fixtures(resource_type=rt, source_text=source_text, connector_hint=scaffold_hint), False


def _checks(
    source_text: str,
    fixtures: dict[str, Any] | None,
    *,
    fixtures_fit_intent: bool,
    probe: bool,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(fixture_test, probe_test) payloads for a draft."""
    fixture_test = _fixture_test_payload(source_text, fixtures) if fixtures else None
    if fixture_test is not None and not fixtures_fit_intent:
        fixture_test["advisory"] = True
    probe_test = probe_policy(source_text, fixtures) if (probe and fixtures and source_text.strip()) else None
    return fixture_test, probe_test


def _needs_repair(
    validation: dict[str, Any],
    fixture_test: dict[str, Any] | None,
    probe_test: dict[str, Any] | None,
    scope_errors: list[str] | None = None,
) -> bool:
    if not validation["valid"]:
        return True
    if scope_errors:
        return True
    if probe_test is not None and not probe_test["passed"]:
        return True
    return fixture_test is not None and not fixture_test.get("passed") and not fixture_test.get("advisory")


def _scope_errors(source_text: str, analysis: IntentAnalysis | None) -> list[str]:
    """What the draft got wrong about its scope: a single-app guard in a
    cross-application policy evaluates one application and silently passes
    the rest."""
    if analysis is None or analysis.scope != SCOPE_CROSS_APP or not source_text.strip():
        return []
    guard = single_app_guard(source_text)
    if guard is None:
        return []
    return [
        f"the draft returns early on the application type ({guard}); a cross-application policy must evaluate "
        "every application's rows and read resource['cluster'] (skip bots by identity_type, and the identity "
        "provider's own account only when its state is the correct end state)"
    ]


def _repair_errors(
    validation: dict[str, Any],
    fixture_test: dict[str, Any] | None,
    probe_test: dict[str, Any] | None,
    scope_errors: list[str],
) -> list[str]:
    errors = list(validation["errors"])
    errors.extend(scope_errors)
    if probe_test and not probe_test["passed"]:
        errors.extend(f"edge-case row failed: {err}" for err in probe_test["errors"])
    if fixture_test and not fixture_test.get("passed") and not fixture_test.get("advisory"):
        errors.append(f"fixture test failed: expected {fixture_test.get('expected')}, got {fixture_test.get('actual')}")
    return errors


def _declare_requires(source_text: str, analysis: IntentAnalysis) -> str:
    if analysis.scope != SCOPE_CROSS_APP:
        return source_text
    return ensure_requires(source_text, analysis.requires)


def _assessability(session: Session | None, org_id: uuid.UUID | None, requires: list[str]) -> list[dict[str, Any]] | None:
    if session is None or org_id is None or not requires:
        return None
    from kestrel.policies.coverage import assess_requires

    return [row.to_dict() for row in assess_requires(session, org_id, requires)]


def generate_policy_draft(
    *,
    intent: str,
    resource_type: str | None = None,
    connector_hint: str | None = None,
    application_instance_id: uuid.UUID | None = None,
    include_fixtures: bool = True,
    session: Session | None = None,
    org_id: uuid.UUID | None = None,
    credentials: LlmCredentials | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Return draft + validation (+ optional fixtures). Never persists or enables.

    Resolution order:
    1. High-confidence intent template (works offline)
    2. Org Settings → AI / ``KESTREL_LLM_*`` env → LLM draft
    3. Unconfigured (no silent ``return True`` stub)

    ``scope`` is ``single_app`` or ``cross_app``; left unset, it is read from
    the connector hint and the intent's wording (``generate_intent``).
    """
    cleaned_intent = intent.strip()
    if not cleaned_intent:
        raise ValueError("intent is required")

    resolved_connector = resolve_connector_hint(
        session,
        org_id,
        connector_hint=connector_hint,
        application_instance_id=application_instance_id,
    )
    connector = normalize_connector_hint(resolved_connector or connector_hint)
    analysis = analyze_intent(cleaned_intent, connector_hint=connector, resource_type=resource_type, scope=scope)
    effective_type = resource_type or analysis.resource_type
    template = match_intent_template(
        cleaned_intent,
        connector_hint=connector,
        resource_type=effective_type,
        scope=analysis.scope,
    )

    creds = credentials
    if creds is None and template is None:
        creds = resolve_llm_credentials(session, org_id)

    provider: str
    used_model: str
    source_text: str
    message: str | None = None
    used_llm = False
    llm_error: str | None = None

    if template is not None:
        source_text = template.source_factory(cleaned_intent)
        provider = _TEMPLATE_PROVIDER
        used_model = _TEMPLATE_PROVIDER
    elif creds is None:
        source_text = ""
        provider = _UNCONFIGURED_PROVIDER
        used_model = _UNCONFIGURED_PROVIDER
        message = _UNCONFIGURED_MESSAGE
    else:
        try:
            source_text = _llm_draft(
                creds=creds,
                intent=cleaned_intent,
                resource_type=effective_type,
                connector_hint=connector,
                analysis=analysis,
            )
            # A cross-application draft reads fields some connectors never
            # collect; it must say so, or a tenant missing them reports
            # "monitored" and finds nothing.
            source_text = _declare_requires(source_text, analysis)
            provider = creds.provider
            used_model = creds.model
            used_llm = True
        except Exception as exc:
            logger.warning("LLM policy draft generation failed", exc_info=True)
            if isinstance(exc, httpx.HTTPStatusError):
                logger.warning(
                    "LLM provider error: status=%s code=%s message=%s",
                    exc.response.status_code,
                    _provider_error_code(exc.response) or "-",
                    _provider_error_message(exc.response) or "-",
                )
            source_text = ""
            provider = _ERROR_PROVIDER
            used_model = _ERROR_PROVIDER
            llm_error = operator_llm_error_message(exc)
            message = llm_error

    validation = _validation_payload(source_text)
    fixtures, fixtures_fit_intent = _resolve_fixtures(
        include_fixtures=include_fixtures,
        intent=cleaned_intent,
        resource_type=effective_type,
        source_text=source_text,
        connector_hint=connector,
        template=template,
        scope=analysis.scope,
    )
    # Probe rows only for model output: templates are reviewed and tested.
    fixture_test, probe_test = _checks(
        source_text, fixtures, fixtures_fit_intent=fixtures_fit_intent, probe=used_llm and validation["valid"]
    )
    scope_errors = _scope_errors(source_text, analysis) if used_llm else []

    # Repair passes: compile errors, a single-app guard in a cross-app draft, a
    # probe-row crash, or a fixture mismatch when the LLM was used. The
    # `creds is not None` test stays in the `if` so the type narrowing reaches
    # _repair_draft below. A second turn runs only when the first still fails
    # and produced something different (a model that returns the same source
    # again will not do better a third time).
    repair_turns = 0
    while (
        used_llm
        and creds is not None
        and repair_turns < _MAX_REPAIR_TURNS
        and _needs_repair(validation, fixture_test, probe_test, scope_errors)
    ):
        repair_turns += 1
        try:
            repaired = _repair_draft(
                creds=creds,
                intent=cleaned_intent,
                resource_type=effective_type,
                connector_hint=connector,
                source_text=source_text,
                errors=_repair_errors(validation, fixture_test, probe_test, scope_errors),
                fixture_test=fixture_test,
                fixtures=fixtures,
                analysis=analysis,
            )
        except Exception:
            logger.warning(
                "LLM policy draft repair failed; returning prior draft with errors",
                exc_info=True,
            )
            break
        repaired = _declare_requires(repaired, analysis)
        no_progress = repaired.strip() == source_text.strip()
        source_text = repaired
        validation = _validation_payload(source_text)
        fixtures, fixtures_fit_intent = _resolve_fixtures(
            include_fixtures=include_fixtures,
            intent=cleaned_intent,
            resource_type=effective_type,
            source_text=source_text,
            connector_hint=connector,
            template=template,
            scope=analysis.scope,
        )
        fixture_test, probe_test = _checks(
            source_text, fixtures, fixtures_fit_intent=fixtures_fit_intent, probe=validation["valid"]
        )
        scope_errors = _scope_errors(source_text, analysis)
        if no_progress:
            break

    requires = analysis.requires if (used_llm or template is not None) and analysis.scope == SCOPE_CROSS_APP else []
    result: dict[str, Any] = {
        "source_text": source_text,
        "provider": provider,
        "model": used_model,
        "message": message,
        "validation": validation,
        "fixtures": fixtures,
        "fixture_test": fixture_test,
        "probe_test": probe_test,
        "scope": analysis.scope,
        "scope_source": analysis.scope_source,
        "intent_analysis": analysis.to_dict(),
        "requires": requires,
        "assessability": _assessability(session, org_id, requires),
        "repair_turns": repair_turns,
    }
    if scope_errors:
        result["scope_errors"] = scope_errors
    not_assessable = [row["name"] for row in result["assessability"] or [] if not row["assessable"]]
    if not_assessable and not message:
        result["message"] = (
            "Not assessable in " + ", ".join(not_assessable) + ": the connector does not collect " + ", ".join(requires)
        )
    if llm_error:
        result["error"] = llm_error
    return result


__all__ = [
    "DEFAULT_LLM_BASE_URL",
    "DEFAULT_LLM_MODEL",
    "chat_completion",
    "generate_policy_draft",
    "operator_llm_error_message",
    "scaffold_fixtures",
]
