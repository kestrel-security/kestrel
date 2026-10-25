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
from kestrel.policies.generate_catalog import (
    connector_catalog_for_prompt,
    match_intent_template,
    normalize_connector_hint,
)
from kestrel.policies.generate_context import resolve_connector_hint
from kestrel.policies.llm_settings import (
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_MODEL,
    LlmCredentials,
    resolve_llm_credentials,
)
from kestrel.policies.resource_schemas import FIXTURE_DEMOS, fixture_demo_for, schema_docs_for_prompt
from kestrel.policies.testing import run_fixture_test_dict

logger = logging.getLogger(__name__)

# Use replace() for schema injection — prompts contain literal `{...}` JSON examples.
_LLM_SYSTEM = """You write Kestrel Python security policies for SaaS posture and event detections.

Return ONLY valid Python source (no markdown fences) defining:
- POLICY_ID (kebab-case slug string)
- TITLE, SEVERITY (low|medium|high|critical), RESOURCE_TYPE
  (identity | grant | tenant_setting | event | application)
- DESCRIPTION, REMEDIATION
- Optional COMPLIANCE = {"framework": ["control"]}

def policy(resource):
    # resource is a dataload dict for RESOURCE_TYPE (see schema below).
    # Return True if compliant; False to open a finding.

def evidence(resource):
    # Return a flat dict of evidence field paths -> values.

Optional helper: time module is available (time.time) for freshness windows on events.
Use only safe Python: no imports, no I/O, no exec. Match existing pack style.
Never enable the policy — this is a human-reviewed draft only.

__SCHEMAS__

__CONNECTOR_CATALOG__
"""

_REPAIR_SYSTEM = """You repair Kestrel Python security policies that failed validation or fixture tests.

Return ONLY corrected valid Python source (no markdown fences). Keep the same intent.
The policy must define POLICY_ID, TITLE, SEVERITY, RESOURCE_TYPE, DESCRIPTION, REMEDIATION,
policy(resource), and evidence(resource). No imports, no I/O, no exec.
Return True from policy() when compliant; False to open a finding.

__SCHEMAS__

__CONNECTOR_CATALOG__
"""

_TEMPLATE_PROVIDER = "template"
_UNCONFIGURED_PROVIDER = "unconfigured"
_ERROR_PROVIDER = "error"

_UNCONFIGURED_MESSAGE = (
    "AI is not configured. Set up Settings → AI (Admin) or KESTREL_LLM_API_KEY, "
    "or use a supported intent template (e.g. Okta admins without MFA)."
)

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


def _system_prompt(*, resource_type: str | None, connector_hint: str | None) -> str:
    catalog = connector_catalog_for_prompt(normalize_connector_hint(connector_hint), resource_type)
    system = _LLM_SYSTEM.replace("__SCHEMAS__", schema_docs_for_prompt(resource_type))
    if catalog:
        return system.replace("__CONNECTOR_CATALOG__", catalog)
    return system.replace("__CONNECTOR_CATALOG__", "")


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
) -> str:
    user_parts = [f"Intent:\n{intent}"]
    if resource_type:
        user_parts.append(f"Preferred RESOURCE_TYPE: {resource_type}")
    connector = normalize_connector_hint(connector_hint)
    if connector:
        user_parts.append(f"Connector / app hint: {connector}")
        catalog = connector_catalog_for_prompt(connector, resource_type)
        if catalog:
            user_parts.append(catalog)

    return chat_completion(
        api_key=creds.api_key,
        base_url=creds.base_url,
        model=creds.model,
        provider=creds.provider,
        messages=[
            {"role": "system", "content": _system_prompt(resource_type=resource_type, connector_hint=connector_hint)},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ],
    )


def _repair_draft(
    *,
    creds: LlmCredentials,
    intent: str,
    resource_type: str | None,
    connector_hint: str | None,
    source_text: str,
    errors: list[str],
    fixture_test: dict[str, Any] | None = None,
) -> str:
    """One optional repair chat turn after validation or fixture-test failure."""
    error_block = "\n".join(f"- {e}" for e in errors) or "- (unknown error)"
    user = f"Intent:\n{intent}\n\nErrors:\n{error_block}\n\nPrevious source:\n{source_text}"
    if fixture_test and not fixture_test.get("passed"):
        user += (
            f"\n\nFixture test failed:\n"
            f"- expected matches: {fixture_test.get('expected')}\n"
            f"- actual matches: {fixture_test.get('actual')}\n"
            f"- missing: {fixture_test.get('missing')}\n"
            f"- unexpected: {fixture_test.get('unexpected')}"
        )
    if resource_type:
        user += f"\n\nPreferred RESOURCE_TYPE: {resource_type}"
    system = _REPAIR_SYSTEM.replace("__SCHEMAS__", schema_docs_for_prompt(resource_type))
    catalog = connector_catalog_for_prompt(normalize_connector_hint(connector_hint), resource_type)
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
    resource_type: str | None,
    source_text: str,
    connector_hint: str | None,
    template: Any,
) -> dict[str, Any] | None:
    if not include_fixtures:
        return None
    rt = resource_type or _resource_type_from_source(source_text)
    return scaffold_fixtures(
        resource_type=rt,
        source_text=source_text,
        connector_hint=connector_hint,
        template=template,
    )


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
) -> dict[str, Any]:
    """Return draft + validation (+ optional fixtures). Never persists or enables.

    Resolution order:
    1. High-confidence intent template (works offline)
    2. Org Settings → AI / ``KESTREL_LLM_*`` env → LLM draft
    3. Unconfigured (no silent ``return True`` stub)
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
    template = match_intent_template(
        cleaned_intent,
        connector_hint=connector,
        resource_type=resource_type,
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
                resource_type=resource_type,
                connector_hint=connector,
            )
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
    fixtures = _resolve_fixtures(
        include_fixtures=include_fixtures,
        resource_type=resource_type,
        source_text=source_text,
        connector_hint=connector,
        template=template,
    )
    fixture_test = _fixture_test_payload(source_text, fixtures) if fixtures else None

    # Repair pass: compile errors or fixture mismatch when LLM was used.
    # The `creds is not None` test stays in the `if` rather than folding into
    # needs_repair so the type narrowing reaches _repair_draft below.
    needs_repair = used_llm and (not validation["valid"] or (fixture_test is not None and not fixture_test.get("passed")))
    if needs_repair and creds is not None:
        repair_errors = list(validation["errors"])
        if fixture_test and not fixture_test.get("passed"):
            repair_errors.append(
                f"fixture test failed: expected {fixture_test.get('expected')}, got {fixture_test.get('actual')}"
            )
        try:
            repaired = _repair_draft(
                creds=creds,
                intent=cleaned_intent,
                resource_type=resource_type,
                connector_hint=connector,
                source_text=source_text,
                errors=repair_errors,
                fixture_test=fixture_test,
            )
            source_text = repaired
            validation = _validation_payload(source_text)
            if include_fixtures:
                fixtures = _resolve_fixtures(
                    include_fixtures=True,
                    resource_type=resource_type,
                    source_text=source_text,
                    connector_hint=connector,
                    template=template,
                )
            fixture_test = _fixture_test_payload(source_text, fixtures) if fixtures else None
        except Exception:
            logger.warning(
                "LLM policy draft repair failed; returning prior draft with errors",
                exc_info=True,
            )

    result: dict[str, Any] = {
        "source_text": source_text,
        "provider": provider,
        "model": used_model,
        "message": message,
        "validation": validation,
        "fixtures": fixtures,
        "fixture_test": fixture_test,
    }
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
