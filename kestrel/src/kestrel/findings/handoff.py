# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding remediation / ticket handoff package.

Builds a structured JSON package and paste-ready Markdown for Jira,
Linear, Slack, or SIEM notes — without a ticketing adapter.

Optional **URL templates** only (no outbound HTTP, secrets, or
TicketProvider — that lives in ``kestrel.ticketing``):

- GitHub Issues: ``https://github.com/{owner}/{repo}/issues/new?title=&body=``
- Jira: operator-supplied Create Issue base URL with ``summary`` +
  ``description`` query params. Accepted bases include Server/DC style
  ``…/secure/CreateIssueDetails!init.jspa`` and
  ``…/secure/CreateIssue!default.jspa`` (or ``/jira/secure/…``). Kestrel
  does not invent a host — omit ``jira_base_url`` to omit the Jira link.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlparse

from sqlalchemy.orm import Session

from kestrel.db.models.finding import Finding
from kestrel.findings.attack_path import attack_path, attack_path_compact
from kestrel.findings.investigation.blast_radius import blast_radius
from kestrel.findings.investigation.compliance import policy_context
from kestrel.findings.investigation.evidence import evidence_with_links
from kestrel.findings.investigation.related import related_findings
from kestrel.findings.investigation.status import list_exceptions
from kestrel.findings.investigation.subject import resolve_subject
from kestrel.findings.listing import finding_summary
from kestrel.findings.playbook import remediation_playbook
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_url

_EVIDENCE_VALUE_MAX = 500
_TICKET_BODY_MAX = 6000
_GITHUB_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")


class TicketUrlConfigError(ValueError):
    """Invalid github_repo or jira_base_url for create-issue URL templates."""


def _truncate_value(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _EVIDENCE_VALUE_MAX:
        return value[: _EVIDENCE_VALUE_MAX - 1] + "…"
    if isinstance(value, (dict, list)):
        raw = json.dumps(value, default=str)
        if len(raw) > _EVIDENCE_VALUE_MAX:
            return raw[: _EVIDENCE_VALUE_MAX - 1] + "…"
        return value
    return value


def build_handoff_package(db: Session, finding: Finding) -> dict[str, Any]:
    """Structured remediation package for ticket / chat handoff."""
    policy = policy_context(db, finding)
    subject = resolve_subject(db, finding)
    evidence = evidence_with_links(db, finding)
    playbook = remediation_playbook(
        remediation=policy.get("remediation") if policy else None,
        subject=subject,
        finding_status=finding.status.value,
        evidence_count=len(evidence),
        finding_id=str(finding.id),
    )
    summary = finding_summary(db, finding)
    radius = blast_radius(db, finding)
    related = related_findings(db, finding)
    exceptions = list_exceptions(db, finding)
    path = attack_path(db, finding)

    return {
        "kind": "kestrel.finding.handoff",
        "generated_at": datetime.now(UTC).isoformat(),
        "finding": {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "age_days": summary.get("age_days"),
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
            "detail_path": f"/findings/{finding.id}",
        },
        "subject": subject,
        "policy": (
            {
                "id": policy.get("id"),
                "slug": policy.get("slug"),
                "title": policy.get("title"),
                "version": policy.get("version"),
                "remediation": policy.get("remediation"),
                "compliance_mappings": policy.get("compliance_mappings") or {},
            }
            if policy
            else None
        ),
        "evidence": [
            {
                "label": row["label"],
                "value": _truncate_value(row.get("value")),
            }
            for row in evidence
        ],
        "remediation_playbook": playbook,
        "exceptions": exceptions,
        "related_findings_count": len(related),
        "blast_radius_open_count": radius.get("open_finding_count", 0),
        "attack_path": attack_path_compact(path),
        "assigned_to": summary.get("assigned_to"),
        "ticket_urls": {},
    }


def _ticket_title(package: dict[str, Any]) -> str:
    finding = package.get("finding") or {}
    title = str(finding.get("title") or "Kestrel finding").strip() or "Kestrel finding"
    return title[:200]


def _ticket_body(package: dict[str, Any]) -> str:
    """Markdown body for create-issue URLs (without the Open ticket section)."""
    body = handoff_markdown(package, include_ticket_links=False)
    if len(body) > _TICKET_BODY_MAX:
        return body[: _TICKET_BODY_MAX - 1] + "…"
    return body


def _normalize_github_repo(github_repo: str | None) -> str | None:
    if github_repo is None:
        return None
    cleaned = github_repo.strip().removeprefix("https://github.com/").removeprefix("http://github.com/")
    cleaned = cleaned.strip("/")
    if not cleaned:
        return None
    if not _GITHUB_REPO_RE.match(cleaned):
        raise TicketUrlConfigError("github_repo must be owner/repo (letters, digits, ., _, -)")
    return cleaned


def _normalize_jira_base_url(jira_base_url: str | None) -> str | None:
    """Validate operator-supplied Jira Create Issue base (https + SSRF guard).

    Expected templates (path included by the operator):
    - ``https://jira.example.com/secure/CreateIssueDetails!init.jspa``
    - ``https://jira.example.com/secure/CreateIssue!default.jspa``
    - ``https://jira.example.com/jira/secure/CreateIssue!default.jspa``
    """
    if jira_base_url is None:
        return None
    cleaned = jira_base_url.strip()
    if not cleaned:
        return None
    parsed = urlparse(cleaned)
    if parsed.scheme != "https":
        raise TicketUrlConfigError("jira_base_url: must use https")
    if not parsed.hostname:
        raise TicketUrlConfigError("jira_base_url: URL is missing a host")
    try:
        validate_connector_url(cleaned, field="jira_base_url")
    except UnsafeConnectorURLError as exc:
        raise TicketUrlConfigError(str(exc)) from exc
    return cleaned.rstrip("?&")


def _append_query(base: str, params: dict[str, str]) -> str:
    query = urlencode(params)
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{query}"


def build_ticket_urls(
    package: dict[str, Any],
    *,
    github_repo: str | None = None,
    jira_base_url: str | None = None,
) -> dict[str, str]:
    """Build create-issue URL templates from handoff content.

    Omits keys when the corresponding config is absent. Does not invent hosts.
    """
    repo = _normalize_github_repo(github_repo)
    jira = _normalize_jira_base_url(jira_base_url)
    if repo is None and jira is None:
        return {}

    title = _ticket_title(package)
    body = _ticket_body(package)
    urls: dict[str, str] = {}

    if repo is not None:
        urls["github_issue"] = f"https://github.com/{repo}/issues/new?{urlencode({'title': title, 'body': body})}"
    if jira is not None:
        urls["jira"] = _append_query(jira, {"summary": title, "description": body})
    return urls


def apply_ticket_urls(
    package: dict[str, Any],
    *,
    github_repo: str | None = None,
    jira_base_url: str | None = None,
) -> dict[str, Any]:
    """Mutate ``package['ticket_urls']`` from optional query/config overrides."""
    package["ticket_urls"] = build_ticket_urls(
        package,
        github_repo=github_repo,
        jira_base_url=jira_base_url,
    )
    return package


def handoff_markdown(package: dict[str, Any], *, include_ticket_links: bool = True) -> str:
    """Paste-ready Markdown for tickets and chat."""
    finding = package["finding"]
    subject = package.get("subject") or {}
    policy = package.get("policy")
    lines: list[str] = [
        f"# {finding['title']}",
        "",
        f"- **Severity:** {finding['severity']}",
        f"- **Status:** {finding['status']}",
        f"- **Finding ID:** `{finding['id']}`",
        f"- **Age (days):** {finding.get('age_days') if finding.get('age_days') is not None else '—'}",
        f"- **Kestrel:** `{finding['detail_path']}`",
        "",
        "## Subject",
        "",
        f"- **Type:** {subject.get('type', '—')}",
        f"- **Label:** {subject.get('label') or subject.get('id') or '—'}",
    ]
    if subject.get("secondary"):
        lines.append(f"- **Detail:** {subject['secondary']}")
    if subject.get("detail_path"):
        lines.append(f"- **Path:** `{subject['detail_path']}`")

    lines.extend(["", "## Policy", ""])
    if policy:
        title = policy.get("title") or policy.get("slug") or "—"
        lines.append(f"- **Policy:** {title}")
        if policy.get("slug"):
            lines.append(f"- **Slug:** `{policy['slug']}`")
        if policy.get("version") is not None:
            lines.append(f"- **Version:** {policy['version']}")
        remediation = policy.get("remediation")
        if remediation:
            lines.extend(["", "### Remediation", "", remediation])
        mappings = policy.get("compliance_mappings") or {}
        if mappings:
            lines.extend(["", "### Compliance", ""])
            for framework, controls in mappings.items():
                ctrl = ", ".join(controls) if isinstance(controls, list) else str(controls)
                lines.append(f"- **{framework}:** {ctrl}")
    else:
        lines.append("_No policy context available._")

    playbook = package.get("remediation_playbook") or []
    if playbook:
        lines.extend(["", "## Playbook", ""])
        for index, step in enumerate(playbook, start=1):
            lines.append(f"{index}. **{step.get('title', 'Step')}** ({step.get('kind', 'step')})")
            instruction = step.get("instruction")
            if instruction:
                lines.append(f"   {instruction}")

    evidence = package.get("evidence") or []
    if evidence:
        lines.extend(["", "## Evidence", ""])
        for row in evidence:
            value = row.get("value")
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, default=str)
            else:
                rendered = "—" if value is None else str(value)
            lines.append(f"- **{row.get('label', 'field')}:** `{rendered}`")

    assignee = package.get("assigned_to")
    if assignee:
        lines.extend(
            [
                "",
                "## Ownership",
                "",
                f"- **Assignee:** {assignee.get('display_name') or assignee.get('email') or assignee.get('id')}",
            ]
        )

    related = package.get("related_findings_count", 0)
    blast = package.get("blast_radius_open_count", 0)
    lines.extend(
        [
            "",
            "## Context",
            "",
            f"- Related findings on subject: {related}",
            f"- Open findings in blast radius: {blast}",
        ]
    )

    attack = package.get("attack_path") or {}
    attack_summary = attack.get("summary")
    if attack_summary:
        lines.extend(["", "## Attack path", "", attack_summary])
        for hop in attack.get("hops") or []:
            explanation = hop.get("explanation")
            if explanation:
                lines.append(f"- {explanation}")

    if include_ticket_links:
        urls = package.get("ticket_urls") or {}
        github = urls.get("github_issue")
        jira = urls.get("jira")
        if github or jira:
            lines.extend(["", "## Open ticket", ""])
            if github:
                lines.append(f"- [Create GitHub issue]({github})")
            if jira:
                lines.append(f"- [Create Jira issue]({jira})")

    lines.extend(
        [
            "",
            f"_Generated by Kestrel at {package.get('generated_at', '')}_",
            "",
        ]
    )
    return "\n".join(lines)
