# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Custom policy authoring: compile/validate Python policies and create
immutable PolicyVersion rows for `source=custom` policies.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.locks import POLICY_EVALUATION, org_advisory_xact_lock
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.findings.lifecycle import repoint_findings_to_current_version, resolve_findings_for_disabled_policy
from kestrel.policies.runtime import (
    CompiledPolicy,
    PolicyCompileError,
    compile_and_validate,
)
from kestrel.policies.runtime.restricted import unknown_name_errors

SOURCE_PREVIEW_LEN = 96

_POLICY_ID_ASSIGN_RE = re.compile(
    r"^(POLICY_ID\s*=\s*)([\"'])([^\"']*)\2",
    re.MULTILINE,
)
_TITLE_ASSIGN_RE = re.compile(
    r"^(TITLE\s*=\s*)([\"'])([^\"']*)\2",
    re.MULTILINE,
)


@dataclass(frozen=True)
class PolicySourceError:
    """A single compile/validate failure, optionally with source location."""

    message: str
    line: int | None = None
    column: int | None = None

    def __str__(self) -> str:
        if self.line is not None and self.column is not None:
            return f"line {self.line}, col {self.column}: {self.message}"
        if self.line is not None:
            return f"line {self.line}: {self.message}"
        return self.message


@dataclass(frozen=True)
class ParsedPolicySource:
    source_text: str
    compiled: CompiledPolicy | None
    errors: list[PolicySourceError]

    @property
    def is_valid(self) -> bool:
        return not self.errors and self.compiled is not None


class PolicyAuthoringError(ValueError):
    """Raised when a write cannot proceed (invalid source, duplicate slug,
    wrong source type). Callers map this to HTTP 400."""


def parse_policy_source(source_text: str) -> ParsedPolicySource:
    """Compile and validate Python policy source without touching the database."""
    try:
        compiled = compile_and_validate(source_text)
    except PolicyCompileError as exc:
        return ParsedPolicySource(
            source_text=source_text,
            compiled=None,
            errors=[
                PolicySourceError(message=exc.message, line=exc.line, column=exc.column),
            ],
        )
    # A name nothing defines (``datetime``, a typo) only fails when a row
    # reaches it, so report it here rather than at evaluation time.
    errors = [
        PolicySourceError(message=err.message, line=err.line, column=err.column) for err in unknown_name_errors(source_text)
    ]
    return ParsedPolicySource(source_text=source_text, compiled=compiled, errors=errors)


def create_custom_policy(
    session: Session,
    *,
    org_id: uuid.UUID,
    source_text: str,
    created_by: str | None = None,
) -> Policy:
    """Creates a `source=custom` Policy + first PolicyVersion from Python text."""
    parsed = parse_policy_source(source_text)
    if not parsed.is_valid or parsed.compiled is None:
        raise PolicyAuthoringError("; ".join(str(e) for e in parsed.errors))

    contract = parsed.compiled.contract
    existing = session.scalars(
        select(Policy).where(Policy.org_id == org_id, Policy.slug == contract.policy_id)
    ).one_or_none()
    if existing is not None:
        raise PolicyAuthoringError(f"policy slug '{contract.policy_id}' already exists in this org")

    policy = Policy(
        id=uuid.uuid4(),
        org_id=org_id,
        slug=contract.policy_id,
        title=contract.title,
        description=contract.description or None,
        source=PolicySource.CUSTOM,
        pack_name=None,
    )
    session.add(policy)
    session.flush()

    version = _new_version(
        session,
        policy=policy,
        version_number=1,
        source_text=parsed.source_text,
        compiled=parsed.compiled,
        is_enabled=True,
        created_by=created_by,
    )
    policy.current_version_id = version.id
    return policy


def publish_new_version(
    session: Session,
    *,
    policy: Policy,
    source_text: str,
    created_by: str | None = None,
) -> PolicyVersion:
    """Appends a new PolicyVersion when source text changed. Only custom policies."""
    if policy.source != PolicySource.CUSTOM:
        raise PolicyAuthoringError(
            "only custom policies can be edited via the API; re-install the pack to update pack policies"
        )

    parsed = parse_policy_source(source_text)
    if not parsed.is_valid or parsed.compiled is None:
        raise PolicyAuthoringError("; ".join(str(e) for e in parsed.errors))

    if parsed.compiled.contract.policy_id != policy.slug:
        raise PolicyAuthoringError(
            f"POLICY_ID in source ('{parsed.compiled.contract.policy_id}') must match existing slug ('{policy.slug}')"
        )

    latest = session.scalars(
        select(PolicyVersion).where(PolicyVersion.policy_id == policy.id).order_by(PolicyVersion.version.desc()).limit(1)
    ).first()

    if latest is not None and latest.source_text == parsed.source_text:
        return latest

    was_enabled = latest.is_enabled if latest is not None else True
    version_number = (latest.version + 1) if latest else 1
    version = _new_version(
        session,
        policy=policy,
        version_number=version_number,
        source_text=parsed.source_text,
        compiled=parsed.compiled,
        is_enabled=was_enabled,
        created_by=created_by,
    )
    policy.current_version_id = version.id
    policy.title = parsed.compiled.contract.title
    policy.description = parsed.compiled.contract.description or None
    repoint_findings_to_current_version(session, policy)
    return version


def set_current_version_enabled(
    session: Session,
    *,
    policy: Policy,
    is_enabled: bool,
    actor_operator_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
) -> PolicyVersion:
    """Toggles evaluation for the current version.

    Disabling resolves the policy's open findings (reason ``policy_disabled``):
    a policy that no longer runs can never resolve them otherwise. Pass
    ``webhook_delivery_ids`` to also schedule ``finding.resolved`` webhooks,
    which the caller enqueues after commit.
    """
    if policy.current_version_id is None:
        raise PolicyAuthoringError("policy has no current version")
    # Serialised with evaluation before any write (see findings.lifecycle).
    org_advisory_xact_lock(session, policy.org_id, POLICY_EVALUATION)
    version = session.get(PolicyVersion, policy.current_version_id)
    if version is None:
        raise PolicyAuthoringError("policy has no current version")
    was_enabled = version.is_enabled
    version.is_enabled = is_enabled
    if was_enabled and not is_enabled:
        resolve_findings_for_disabled_policy(
            session,
            policy,
            actor_operator_id=actor_operator_id,
            webhook_delivery_ids=webhook_delivery_ids,
        )
    return version


def list_policy_versions(session: Session, *, policy: Policy) -> list[dict]:
    """List immutable versions for a policy (newest first), with preview/hash.

    Works for pack and custom. Does not mutate; activation is custom-only.
    """
    versions = session.scalars(
        select(PolicyVersion).where(PolicyVersion.policy_id == policy.id).order_by(PolicyVersion.version.desc())
    ).all()
    return [policy_version_summary(version, current_version_id=policy.current_version_id) for version in versions]


def policy_version_summary(version: PolicyVersion, *, current_version_id: uuid.UUID | None) -> dict:
    """Serialize a PolicyVersion for history listing."""
    collapsed = " ".join(version.source_text.split())
    preview = collapsed[: SOURCE_PREVIEW_LEN - 1] + "…" if len(collapsed) > SOURCE_PREVIEW_LEN else collapsed
    digest = hashlib.sha256(version.source_text.encode("utf-8")).hexdigest()
    return {
        "id": version.id,
        "version": version.version,
        "created_at": version.created_at.isoformat() if version.created_at else None,
        "severity": version.severity.value,
        "is_enabled": version.is_enabled,
        "is_current": current_version_id is not None and version.id == current_version_id,
        "source_preview": preview,
        "source_hash": digest[:12],
        "created_by": version.created_by,
    }


def activate_policy_version(
    session: Session,
    *,
    policy: Policy,
    version_id: uuid.UUID,
) -> PolicyVersion:
    """Point ``current_version_id`` at an existing immutable version (custom only).

    Pack / system policies cannot roll back via the API — re-install the pack.
    Syncs policy title/description from the activated source when it still parses.
    Preserves the previous current version's ``is_enabled`` on the activated row
    so enablement feels like a policy-level toggle across rollback.
    """
    if policy.source != PolicySource.CUSTOM:
        raise PolicyAuthoringError(
            "only custom policies support version rollback; re-install the pack to update pack policies"
        )

    version = session.get(PolicyVersion, version_id)
    if version is None or version.policy_id != policy.id:
        raise PolicyAuthoringError("version not found for this policy")

    previous_enabled: bool | None = None
    if policy.current_version_id is not None and policy.current_version_id != version.id:
        previous = session.get(PolicyVersion, policy.current_version_id)
        if previous is not None:
            previous_enabled = previous.is_enabled

    policy.current_version_id = version.id
    if previous_enabled is not None:
        version.is_enabled = previous_enabled

    parsed = parse_policy_source(version.source_text)
    # A stored version that compiles still refreshes the title even when an
    # authoring-time check (unknown names) would now reject it on save.
    if parsed.compiled is not None:
        policy.title = parsed.compiled.contract.title
        policy.description = parsed.compiled.contract.description or None
    repoint_findings_to_current_version(session, policy)
    return version


def rewrite_policy_identity(source_text: str, *, new_slug: str, new_title: str) -> str:
    """Rewrite top-level POLICY_ID / TITLE string assignments for a fork copy."""

    def _escape(value: str, quote: str) -> str:
        if quote == '"':
            return value.replace("\\", "\\\\").replace('"', '\\"')
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _replace_id(match: re.Match[str]) -> str:
        quote = match.group(2)
        return f"{match.group(1)}{quote}{_escape(new_slug, quote)}{quote}"

    rewritten, id_count = _POLICY_ID_ASSIGN_RE.subn(_replace_id, source_text, count=1)
    if id_count != 1:
        raise PolicyAuthoringError("source text missing POLICY_ID assignment")

    def _replace_title(match: re.Match[str]) -> str:
        quote = match.group(2)
        return f"{match.group(1)}{quote}{_escape(new_title, quote)}{quote}"

    rewritten, title_count = _TITLE_ASSIGN_RE.subn(_replace_title, rewritten, count=1)
    if title_count == 0:
        escaped_title = _escape(new_title, '"')
        rewritten, id_again = _POLICY_ID_ASSIGN_RE.subn(
            lambda m: f'{m.group(0)}\nTITLE = "{escaped_title}"',
            rewritten,
            count=1,
        )
        if id_again != 1:
            raise PolicyAuthoringError("could not insert TITLE after POLICY_ID")
    return rewritten


def allocate_fork_slug(session: Session, *, org_id: uuid.UUID, base_slug: str) -> str:
    """Pick a unique slug: ``{base}-custom``, then ``{base}-fork``, then ``-custom-N``."""
    candidates = [f"{base_slug}-custom", f"{base_slug}-fork"]
    for candidate in candidates:
        if not _slug_taken(session, org_id=org_id, slug=candidate):
            return candidate
    n = 2
    while True:
        candidate = f"{base_slug}-custom-{n}"
        if not _slug_taken(session, org_id=org_id, slug=candidate):
            return candidate
        n += 1


def fork_pack_policy(
    session: Session,
    *,
    policy: Policy,
    created_by: str | None = None,
) -> Policy:
    """Copy a pack policy into a new disabled ``source=custom`` policy.

    The pack policy is left unchanged. Slug is unique (``{slug}-custom`` / collision
    suffixes); title indicates a fork; evaluation starts disabled.
    """
    if policy.source != PolicySource.PACK:
        raise PolicyAuthoringError("only pack policies can be forked")
    if policy.current_version_id is None:
        raise PolicyAuthoringError("policy has no current version")
    version = session.get(PolicyVersion, policy.current_version_id)
    if version is None:
        raise PolicyAuthoringError("policy has no current version")

    new_slug = allocate_fork_slug(session, org_id=policy.org_id, base_slug=policy.slug)
    new_title = f"{policy.title} (custom fork)"
    rewritten = rewrite_policy_identity(
        version.source_text,
        new_slug=new_slug,
        new_title=new_title,
    )
    forked = create_custom_policy(
        session,
        org_id=policy.org_id,
        source_text=rewritten,
        created_by=created_by,
    )
    set_current_version_enabled(session, policy=forked, is_enabled=False)
    return forked


def _slug_taken(session: Session, *, org_id: uuid.UUID, slug: str) -> bool:
    existing = session.scalars(select(Policy.id).where(Policy.org_id == org_id, Policy.slug == slug).limit(1)).first()
    return existing is not None


def _new_version(
    session: Session,
    *,
    policy: Policy,
    version_number: int,
    source_text: str,
    compiled: CompiledPolicy,
    is_enabled: bool,
    created_by: str | None,
) -> PolicyVersion:
    contract = compiled.contract
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version=version_number,
        source_text=source_text,
        severity=Severity(contract.severity),
        remediation=contract.remediation,
        compliance_mappings=contract.compliance or None,
        is_enabled=is_enabled,
        created_by=created_by,
    )
    session.add(version)
    session.flush()
    return version
