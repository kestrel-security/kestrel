# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""GitHub Issues TicketProvider — create issue via REST API."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx

from kestrel.ticketing.protocol import TicketCreateRequest, TicketCreateResult

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "Kestrel-Ticketing/1.0"
TIMEOUT_SECONDS = 15.0


class GitHubIssuesProviderError(ValueError):
    """Invalid config or upstream GitHub error."""


class GitHubIssuesProvider:
    provider_id = "github_issues"

    def create_issue(
        self,
        *,
        token: str,
        config: dict[str, Any],
        request: TicketCreateRequest,
        http_client: httpx.Client | None = None,
        dry_run: bool = False,
    ) -> TicketCreateResult:
        repo = _normalize_repo(config.get("repo") or config.get("github_repo"))
        owner, name = repo.split("/", 1)
        if dry_run:
            return TicketCreateResult(
                external_id="dry-run",
                url=f"https://github.com/{owner}/{name}/issues/new",
                raw={"dry_run": True, "repo": repo, "title": request.title},
            )

        path = f"/repos/{quote(owner)}/{quote(name)}/issues"
        payload: dict[str, Any] = {"title": request.title, "body": request.body}
        if request.labels:
            payload["labels"] = list(request.labels)

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        client = http_client or httpx.Client(timeout=TIMEOUT_SECONDS)
        owns_client = http_client is None
        try:
            response = client.post(f"{GITHUB_API_BASE}{path}", json=payload, headers=headers)
        finally:
            if owns_client:
                client.close()

        if response.status_code >= 400:
            raise GitHubIssuesProviderError(
                f"GitHub Issues create failed ({response.status_code}): {_safe_error_body(response)}"
            )
        data = response.json()
        html_url = data.get("html_url")
        number = data.get("number")
        if not html_url or number is None:
            raise GitHubIssuesProviderError("GitHub response missing html_url/number")
        return TicketCreateResult(external_id=str(number), url=str(html_url), raw=data)


def _normalize_repo(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise GitHubIssuesProviderError("config.repo is required (owner/repo)")
    cleaned = raw.strip()
    cleaned = cleaned.removeprefix("https://github.com/").removeprefix("http://github.com/")
    cleaned = cleaned.removesuffix(".git").strip("/")
    if not _REPO_RE.match(cleaned):
        raise GitHubIssuesProviderError("config.repo must look like owner/repo")
    return cleaned


def _safe_error_body(response: httpx.Response) -> str:
    try:
        data = response.json()
        message = data.get("message") if isinstance(data, dict) else None
        if isinstance(message, str) and message:
            return message[:200]
    except ValueError:  # not JSON
        pass
    return (response.text or "")[:200]
