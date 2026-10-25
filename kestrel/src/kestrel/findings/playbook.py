# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Guided remediation playbook steps for finding investigation.

Builds a structured checklist beyond the policy `remediation` prose string.
Steps are manual/guided only — no automated remediations or approval gates.
"""

from __future__ import annotations

import re
from typing import Any

_LEADING_MARKER = re.compile(r"^[\s]*(?:(?:\d+)[.)]|[-*•])\s+")


def split_remediation_actions(remediation: str | None) -> list[str]:
    """Turn policy remediation prose into discrete operator actions.

    Prefers numbered/bulleted lines; otherwise splits on ``; ``. A single
    sentence (including ``or`` alternatives) stays one action so operators
    choose the path themselves.
    """
    if remediation is None:
        return []
    text = remediation.strip()
    if not text:
        return []

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) > 1:
        cleaned = [_LEADING_MARKER.sub("", ln).strip() for ln in lines]
        cleaned = [c.rstrip(".") for c in cleaned if c]
        if len(cleaned) > 1:
            return cleaned

    if "; " in text:
        parts = [p.strip().rstrip(".") for p in text.split(";") if p.strip()]
        if len(parts) > 1:
            return parts

    return [text]


def remediation_playbook(
    *,
    remediation: str | None,
    subject: dict[str, Any],
    finding_status: str,
    evidence_count: int = 0,
    finding_id: str | None = None,
) -> list[dict[str, Any]]:
    """Ordered checklist for SecOps handoff on a finding detail page.

    Each step: ``id``, ``kind`` (investigate|remediate|verify|document),
    ``title``, ``instruction``, optional ``href`` deep-link (in-app or
    provider console URL).
    """
    label = subject.get("label") or subject.get("type") or "subject"
    subject_href = subject.get("detail_path") or subject.get("connector_path") or subject.get("findings_list_path")
    fix_href = subject.get("provider_console_url") or subject.get("connector_path") or subject.get("inventory_path")
    findings_href = subject.get("findings_list_path")
    verify_href = f"/findings/{finding_id}#verify" if finding_id else "/connectors"

    steps: list[dict[str, Any]] = [
        {
            "id": "review_subject",
            "kind": "investigate",
            "title": "Review the affected subject",
            "instruction": (
                f"Confirm {label} still violates the policy in the source SaaS "
                "(use provider console or connector sync data)."
            ),
            "href": subject_href,
        },
        {
            "id": "review_evidence",
            "kind": "investigate",
            "title": "Confirm evidence",
            "instruction": (
                f"Review the {evidence_count} evidence row(s) and related findings on this subject."
                if evidence_count > 0
                else "No evidence rows were recorded — check related findings and the connector."
            ),
            "href": findings_href,
        },
    ]

    actions = split_remediation_actions(remediation)
    if actions:
        multi = len(actions) > 1
        for index, action in enumerate(actions, start=1):
            steps.append(
                {
                    "id": f"apply_fix_{index}",
                    "kind": "remediate",
                    "title": (f"Apply fix ({index}/{len(actions)})" if multi else "Apply the policy remediation"),
                    "instruction": action,
                    "href": fix_href,
                }
            )
    else:
        steps.append(
            {
                "id": "document_fix",
                "kind": "remediate",
                "title": "Determine a fix path",
                "instruction": (
                    "This policy version has no remediation text. Document the fix "
                    "in the SaaS console, or file an exception with a clear reason."
                ),
                "href": fix_href,
            }
        )

    steps.append(
        {
            "id": "verify_resync",
            "kind": "verify",
            "title": "Re-check remediation on live inventory",
            "instruction": (
                "After changing the SaaS side, use Verify remediation to dry-run "
                "the policy against live inventory for this subject. Optionally "
                "trigger a connector sync so evaluation can auto-resolve the finding."
            ),
            "href": verify_href,
        }
    )

    status = (finding_status or "").lower()
    if status == "open":
        steps.append(
            {
                "id": "close_finding",
                "kind": "document",
                "title": "Resolve or file an exception",
                "instruction": (
                    "If verified fixed, mark the finding resolved. If the risk is "
                    "accepted, create an exception with an expiry and owner context. "
                    "To defer temporarily, mute/snooze with a required expiry — not suppress."
                ),
                "href": None,
            }
        )
    elif status == "exception":
        steps.append(
            {
                "id": "review_exception",
                "kind": "document",
                "title": "Review the active exception",
                "instruction": "Confirm the exception reason and expiry still match the accepted risk.",
                "href": None,
            }
        )
    elif status == "muted":
        steps.append(
            {
                "id": "review_mute",
                "kind": "document",
                "title": "Review the mute / snooze",
                "instruction": (
                    "Muted findings are temporary deferrals. When the mute expires "
                    "(or sooner), unmute and triage — resolve, exception, or suppress."
                ),
                "href": None,
            }
        )

    return steps
