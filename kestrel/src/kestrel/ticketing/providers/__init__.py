# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Built-in TicketProvider implementations."""

from kestrel.ticketing.providers.github_issues import GitHubIssuesProvider
from kestrel.ticketing.providers.jira_cloud import JiraCloudProvider

__all__ = ["GitHubIssuesProvider", "JiraCloudProvider"]
