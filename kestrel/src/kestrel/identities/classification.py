# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Resolve every identity's ``worker_type`` from connector facts and operator rules.

The stored column is authoritative for policies, the Identities API, and
dashboards, so this pass runs after every sync that touched the directory and
again whenever the rules change. An explicit rule outranks the provider's
profile field (operator intent wins); a rule never relabels a ``service``
account, because bots are not people and a domain rule would otherwise turn
every bot into an employee.
"""

from __future__ import annotations

import fnmatch
import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kestrel.db.base import is_active
from kestrel.db.models.access import Group, GroupMembership
from kestrel.db.models.application import Application, ApplicationInstance
from kestrel.db.models.identity import WORKER_TYPES, Identity, WorkerType, coerce_worker_type
from kestrel.db.models.identity_classification import MATCH_KINDS, OrgIdentityClassificationRule

RULE_SOURCE_PREFIX = "rule:"


class ClassificationRuleError(ValueError):
    """A rule the operator submitted cannot be applied."""


@dataclass(frozen=True)
class RuleSpec:
    """One rule as submitted (or stored); ``priority`` is its position."""

    worker_type: str
    match_kind: str
    match_value: str
    application_type: str | None = None
    label: str | None = None
    is_enabled: bool = True
    id: uuid.UUID | None = None


@dataclass(frozen=True)
class AccountFacts:
    """What a rule may look at for one account."""

    email: str | None
    application_type: str | None
    org_unit_path: str | None
    user_type: str | None
    group_names: Sequence[str]
    connector_worker_type: str


def _normalize_domain(value: str) -> str:
    cleaned = value.strip().lower().lstrip("@")
    if not cleaned or "." not in cleaned or " " in cleaned:
        raise ClassificationRuleError(f"email_domain must be a domain such as vendor.example, got {value!r}")
    return cleaned


def validate_rule(spec: RuleSpec) -> RuleSpec:
    """The spec with its values normalized, or ``ClassificationRuleError``."""
    worker_type = spec.worker_type.strip().lower()
    if worker_type not in WORKER_TYPES or worker_type == WorkerType.UNKNOWN.value:
        choices = ", ".join(sorted(WORKER_TYPES - {WorkerType.UNKNOWN.value}))
        raise ClassificationRuleError(f"worker_type must be one of {choices}, got {spec.worker_type!r}")
    kind = spec.match_kind.strip().lower()
    if kind not in MATCH_KINDS:
        raise ClassificationRuleError(f"match_kind must be one of {', '.join(MATCH_KINDS)}, got {spec.match_kind!r}")
    value = spec.match_value.strip()
    if not value:
        raise ClassificationRuleError("match_value is required")
    if kind == "email_domain":
        value = _normalize_domain(value)
    elif kind == "org_unit_path_prefix":
        if not value.startswith("/"):
            raise ClassificationRuleError(f"org_unit_path_prefix must start with '/', got {value!r}")
        value = value.rstrip("/") or "/"
    elif kind == "application_type":
        value = value.lower()
    application_type = (spec.application_type or "").strip().lower() or None
    label = (spec.label or "").strip() or None
    if label and len(label) > 200:
        raise ClassificationRuleError("label must be at most 200 characters")
    return RuleSpec(
        worker_type=worker_type,
        match_kind=kind,
        match_value=value,
        application_type=application_type,
        label=label,
        is_enabled=spec.is_enabled,
        id=spec.id,
    )


def _domain_matches(email: str | None, domain: str) -> bool:
    if not email or "@" not in email:
        return False
    host = email.rsplit("@", 1)[1].strip().lower()
    return host == domain or host.endswith("." + domain)


def _path_has_prefix(path: str | None, prefix: str) -> bool:
    if not path:
        return False
    current = path.rstrip("/") or "/"
    if prefix == "/":
        return True
    return current == prefix or current.startswith(prefix + "/")


def rule_matches(rule: RuleSpec, facts: AccountFacts) -> bool:
    if not rule.is_enabled:
        return False
    if rule.application_type and (facts.application_type or "").lower() != rule.application_type:
        return False
    kind, value = rule.match_kind, rule.match_value
    if kind == "email_domain":
        return _domain_matches(facts.email, value)
    if kind == "org_unit_path_prefix":
        return _path_has_prefix(facts.org_unit_path, value)
    if kind == "group_name":
        return any(fnmatch.fnmatchcase(name.lower(), value.lower()) for name in facts.group_names if name)
    if kind == "user_type":
        return bool(facts.user_type) and fnmatch.fnmatchcase(str(facts.user_type).lower(), value.lower())
    if kind == "application_type":
        return (facts.application_type or "").lower() == value
    return False


def resolve_worker_type(rules: Iterable[RuleSpec], facts: AccountFacts) -> tuple[str, str | None]:
    """``(worker_type, worker_type_source)`` for one account.

    Rules are tried in order and the first match wins, unless the provider
    already knows the account is a bot. With no match the connector's value
    stands, with source ``connector`` when it says anything at all.
    """
    connector_value = coerce_worker_type(facts.connector_worker_type)
    if connector_value != WorkerType.SERVICE.value:
        for rule in rules:
            if rule_matches(rule, facts):
                return rule.worker_type, f"{RULE_SOURCE_PREFIX}{rule.id}" if rule.id else RULE_SOURCE_PREFIX.rstrip(":")
    if connector_value == WorkerType.UNKNOWN.value:
        return connector_value, None
    return connector_value, "connector"


def _spec_from_row(row: OrgIdentityClassificationRule) -> RuleSpec:
    return RuleSpec(
        worker_type=row.worker_type,
        match_kind=row.match_kind,
        match_value=row.match_value,
        application_type=row.application_type,
        label=row.label,
        is_enabled=row.is_enabled,
        id=row.id,
    )


def list_rules(session: Session, org_id: uuid.UUID) -> list[OrgIdentityClassificationRule]:
    return list(
        session.scalars(
            select(OrgIdentityClassificationRule)
            .where(OrgIdentityClassificationRule.org_id == org_id)
            .order_by(OrgIdentityClassificationRule.priority, OrgIdentityClassificationRule.created_at)
        ).all()
    )


def load_rules(session: Session, org_id: uuid.UUID) -> list[RuleSpec]:
    return [_spec_from_row(row) for row in list_rules(session, org_id)]


def replace_rules(
    session: Session,
    org_id: uuid.UUID,
    specs: Sequence[RuleSpec],
    *,
    actor_operator_id: uuid.UUID | None = None,
) -> list[OrgIdentityClassificationRule]:
    """Store ``specs`` as the org's rule list, in the given order. Validates first
    so a bad rule leaves the existing list untouched."""
    validated = [validate_rule(spec) for spec in specs]
    existing = {row.id: row for row in list_rules(session, org_id)}
    kept: list[OrgIdentityClassificationRule] = []
    for position, spec in enumerate(validated):
        row = existing.pop(spec.id, None) if spec.id is not None else None
        if row is None:
            row = OrgIdentityClassificationRule(
                id=spec.id or uuid.uuid4(),
                org_id=org_id,
                created_by_operator_id=actor_operator_id,
            )
            session.add(row)
        row.priority = position
        row.is_enabled = spec.is_enabled
        row.worker_type = spec.worker_type
        row.match_kind = spec.match_kind
        row.match_value = spec.match_value
        row.application_type = spec.application_type
        row.label = spec.label
        kept.append(row)
    if existing:
        session.execute(delete(OrgIdentityClassificationRule).where(OrgIdentityClassificationRule.id.in_(list(existing))))
    session.flush()
    return kept


def _account_facts(session: Session, org_id: uuid.UUID) -> list[tuple[Identity, AccountFacts]]:
    group_names: dict[uuid.UUID, list[str]] = defaultdict(list)
    for identity_id, name in session.execute(
        select(GroupMembership.identity_id, Group.name)
        .join(Group, Group.id == GroupMembership.group_id)
        .where(GroupMembership.org_id == org_id, is_active(GroupMembership), is_active(Group))
    ).all():
        group_names[identity_id].append(str(name))
    rows = session.execute(
        select(Identity, Application.application_type)
        .join(ApplicationInstance, ApplicationInstance.id == Identity.application_instance_id)
        .join(Application, Application.id == ApplicationInstance.application_id)
        .where(Identity.org_id == org_id, is_active(Identity))
    ).all()
    out: list[tuple[Identity, AccountFacts]] = []
    for identity, application_type in rows:
        attributes: dict[str, Any] = identity.attributes or {}
        connector_value = attributes.get("connector_worker_type")
        if connector_value is None and not (identity.worker_type_source or "").startswith(RULE_SOURCE_PREFIX):
            connector_value = identity.worker_type
        out.append(
            (
                identity,
                AccountFacts(
                    email=identity.email,
                    application_type=getattr(application_type, "value", application_type),
                    org_unit_path=attributes.get("org_unit_path"),
                    user_type=attributes.get("user_type"),
                    group_names=group_names.get(identity.id, []),
                    connector_worker_type=coerce_worker_type(connector_value),
                ),
            )
        )
    return out


def reclassify_identities(session: Session, org_id: uuid.UUID, *, rules: Sequence[RuleSpec] | None = None) -> int:
    """Rewrite ``worker_type`` / ``worker_type_source`` for every active identity
    in the org. Returns the number of rows that changed. Writes no change-feed
    events: a rule edit is operator configuration, not provider drift."""
    active_rules = load_rules(session, org_id) if rules is None else list(rules)
    changed = 0
    for identity, facts in _account_facts(session, org_id):
        worker_type, source = resolve_worker_type(active_rules, facts)
        if identity.worker_type != worker_type or identity.worker_type_source != source:
            identity.worker_type = worker_type
            identity.worker_type_source = source
            changed += 1
    session.flush()
    return changed


def preview_rules(session: Session, org_id: uuid.UUID, specs: Sequence[RuleSpec]) -> dict[str, Any]:
    """What ``specs`` would do, without writing: counts per worker type and how
    many accounts would change."""
    validated = [validate_rule(spec) for spec in specs]
    counts: dict[str, int] = dict.fromkeys(sorted(WORKER_TYPES), 0)
    changed = 0
    matched_by_rule: list[int] = [0] * len(validated)
    for identity, facts in _account_facts(session, org_id):
        worker_type, _source = resolve_worker_type(validated, facts)
        counts[worker_type] = counts.get(worker_type, 0) + 1
        if worker_type != identity.worker_type:
            changed += 1
        if facts.connector_worker_type != WorkerType.SERVICE.value:
            for index, rule in enumerate(validated):
                if rule_matches(rule, facts):
                    matched_by_rule[index] += 1
                    break
    return {"counts": counts, "changed": changed, "matched_by_rule": matched_by_rule}


def rules_out(rows: Iterable[OrgIdentityClassificationRule]) -> dict[str, Any]:
    return {
        "rules": [row.to_dict() for row in rows],
        "match_kinds": list(MATCH_KINDS),
        "worker_types": sorted(WORKER_TYPES - {WorkerType.UNKNOWN.value}),
    }
