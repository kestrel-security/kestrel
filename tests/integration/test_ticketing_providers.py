# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- ``TicketProvider`` implementations (``ticketing.providers.*``).

Every provider accepts an injectable ``http_client``, so these tests drive
real provider code against ``httpx.MockTransport`` instead of a live
tracker. Base/repo URLs still pass through the SSRF guard, so tests use
public IP literals the guard accepts without a DNS lookup.
"""

from __future__ import annotations

import httpx
import pytest
from kestrel.ticketing.protocol import TicketCreateRequest
from kestrel.ticketing.providers.github_issues import GitHubIssuesProvider, GitHubIssuesProviderError
from kestrel.ticketing.providers.jira_cloud import JiraCloudProvider, JiraCloudProviderError

_REQUEST = TicketCreateRequest(title="Rotate a leaked credential", body="Full body", labels=["kestrel", "severity:high"])


def test_github_issues_create_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/repos/example-org/example-repo/issues"
        assert request.headers["Authorization"] == "Bearer test-token"
        return httpx.Response(201, json={"html_url": "https://github.com/example-org/example-repo/issues/42", "number": 42})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = GitHubIssuesProvider().create_issue(
        token="test-token",
        config={"repo": "example-org/example-repo"},
        request=_REQUEST,
        http_client=client,
    )

    assert result.external_id == "42"
    assert result.url == "https://github.com/example-org/example-repo/issues/42"


def test_github_issues_accepts_a_pasted_github_url_for_repo():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/example-org/example-repo/issues"
        return httpx.Response(201, json={"html_url": "https://github.com/example-org/example-repo/issues/1", "number": 1})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = GitHubIssuesProvider().create_issue(
        token="t",
        config={"repo": "https://github.com/example-org/example-repo.git"},
        request=_REQUEST,
        http_client=client,
    )
    assert result.external_id == "1"


def test_github_issues_raises_on_upstream_error_with_message_from_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"message": "Validation Failed"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubIssuesProviderError, match="Validation Failed"):
        GitHubIssuesProvider().create_issue(
            token="t", config={"repo": "example-org/example-repo"}, request=_REQUEST, http_client=client
        )


def test_github_issues_dry_run_never_touches_the_transport():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("dry_run must not make an HTTP call")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = GitHubIssuesProvider().create_issue(
        token="t", config={"repo": "example-org/example-repo"}, request=_REQUEST, http_client=client, dry_run=True
    )
    assert result.external_id == "dry-run"


def test_github_issues_requires_repo_config():
    with pytest.raises(GitHubIssuesProviderError):
        GitHubIssuesProvider().create_issue(token="t", config={}, request=_REQUEST)


def test_jira_cloud_create_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/rest/api/3/issue"
        assert request.headers["Authorization"].startswith("Basic ")
        return httpx.Response(201, json={"key": "SEC-123"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = JiraCloudProvider().create_issue(
        token="api-token",
        config={"base_url": "https://8.8.8.8", "project_key": "SEC", "email": "bot@example.test"},
        request=_REQUEST,
        http_client=client,
    )

    assert result.external_id == "SEC-123"
    assert result.url.endswith("/browse/SEC-123")


def test_jira_cloud_dry_run_never_touches_the_transport():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("dry_run must not make an HTTP call")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = JiraCloudProvider().create_issue(
        token="t",
        config={"base_url": "https://8.8.8.8", "project_key": "SEC", "email": "bot@example.test"},
        request=_REQUEST,
        http_client=client,
        dry_run=True,
    )
    assert result.external_id == "SEC-DRYRUN"


def test_jira_cloud_rejects_a_private_base_url():
    with pytest.raises(JiraCloudProviderError):
        JiraCloudProvider().create_issue(
            token="t",
            config={"base_url": "http://127.0.0.1", "project_key": "SEC", "email": "bot@example.test"},
            request=_REQUEST,
        )


def test_jira_cloud_raises_on_upstream_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"errorMessages": ["project key is required"]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(JiraCloudProviderError, match="project key is required"):
        JiraCloudProvider().create_issue(
            token="t",
            config={"base_url": "https://8.8.8.8", "project_key": "SEC", "email": "bot@example.test"},
            request=_REQUEST,
            http_client=client,
        )


def test_jira_cloud_requires_project_key():
    with pytest.raises(JiraCloudProviderError):
        JiraCloudProvider().create_issue(
            token="t", config={"base_url": "https://8.8.8.8", "email": "bot@example.test"}, request=_REQUEST
        )
