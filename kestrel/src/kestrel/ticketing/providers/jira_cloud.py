# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Jira Cloud TicketProvider — create issue via REST API v3."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_url
from kestrel.ticketing.protocol import TicketCreateRequest, TicketCreateResult

USER_AGENT = "Kestrel-Ticketing/1.0"
TIMEOUT_SECONDS = 15.0


class JiraCloudProviderError(ValueError):
    """Invalid config or upstream Jira error."""


class JiraCloudProvider:
    provider_id = "jira_cloud"

    def create_issue(
        self,
        *,
        token: str,
        config: dict[str, Any],
        request: TicketCreateRequest,
        http_client: httpx.Client | None = None,
        dry_run: bool = False,
    ) -> TicketCreateResult:
        base_url = _normalize_base_url(config.get("base_url") or config.get("jira_base_url"))
        project_key = _require_str(config.get("project_key"), "config.project_key")
        issue_type = str(config.get("issue_type") or "Task").strip() or "Task"
        email = config.get("email") or config.get("jira_email")
        if not isinstance(email, str) or not email.strip():
            raise JiraCloudProviderError("config.email is required (Atlassian account email)")
        email = email.strip()

        if dry_run:
            browse = urljoin(base_url.rstrip("/") + "/", f"browse/{project_key}-DRYRUN")
            return TicketCreateResult(
                external_id=f"{project_key}-DRYRUN",
                url=browse,
                raw={"dry_run": True, "project_key": project_key, "title": request.title},
            )

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": request.title[:255],
                "issuetype": {"name": issue_type},
                "description": _plain_text_adf(request.body),
            }
        }
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        url = urljoin(base_url.rstrip("/") + "/", "rest/api/3/issue")
        # Re-check SSRF immediately before outbound call.
        try:
            validate_connector_url(url, field="jira_create_url", require_https=True)
        except UnsafeConnectorURLError as exc:
            raise JiraCloudProviderError(str(exc)) from exc

        client = http_client or httpx.Client(timeout=TIMEOUT_SECONDS)
        owns_client = http_client is None
        try:
            response = client.post(url, json=payload, headers=headers)
        finally:
            if owns_client:
                client.close()

        if response.status_code >= 400:
            raise JiraCloudProviderError(f"Jira create failed ({response.status_code}): {_safe_error_body(response)}")
        data = response.json()
        key = data.get("key")
        if not isinstance(key, str) or not key:
            raise JiraCloudProviderError("Jira response missing key")
        browse = urljoin(base_url.rstrip("/") + "/", f"browse/{key}")
        return TicketCreateResult(external_id=key, url=browse, raw=data)


def _normalize_base_url(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise JiraCloudProviderError("config.base_url is required (https://…atlassian.net)")
    cleaned = raw.strip().rstrip("/")
    # Operators sometimes paste a create-issue deep link; strip to origin.
    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.netloc:
        cleaned = f"{parsed.scheme}://{parsed.netloc}"
    try:
        validate_connector_url(cleaned, field="base_url", require_https=True)
    except UnsafeConnectorURLError as exc:
        raise JiraCloudProviderError(str(exc)) from exc
    return cleaned


def _require_str(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise JiraCloudProviderError(f"{field} is required")
    return raw.strip()


def _plain_text_adf(text: str) -> dict[str, Any]:
    """Minimal Atlassian Document Format paragraph for issue description."""
    content = text if text.strip() else "(no body)"
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": content[:30000]}],
            }
        ],
    }


def _safe_error_body(response: httpx.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            errors = data.get("errorMessages") or data.get("errors")
            if isinstance(errors, list) and errors:
                return str(errors[0])[:200]
            if isinstance(errors, dict) and errors:
                return str(next(iter(errors.values())))[:200]
            msg = data.get("message")
            if isinstance(msg, str) and msg:
                return msg[:200]
    except ValueError:  # not JSON
        pass
    return (response.text or "")[:200]
