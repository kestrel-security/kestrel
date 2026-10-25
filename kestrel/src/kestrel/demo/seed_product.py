# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Seed the parts of the product no connector can ever fill.

Connector sync produces inventory, graph, changes, and findings. Everything an
*operator* does afterwards -- triaging, excepting, muting, assigning, noting,
watching, ticketing, wiring webhooks, building boards -- is written only by an
API handler, so a freshly synced demo has empty tables behind a dozen working
features. This module writes those rows.

Two rules:

* Prefer the real service function (`add_note`, `watch_finding`,
  `create_endpoint`, ...) so the seed exercises the same code path the product
  does, including validation and encryption.
* Construct rows directly only where the service performs I/O a seeder must not:
  `create_ticket_for_finding` calls the live tracker, `WebhookDelivery` is
  written by the Celery worker, and `capture_posture_snapshot` recomputes from
  *current* state, so ninety backdated calls would draw ninety identical points.

Everything is deterministic: same seed, same demo.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.audit.service import record_audit_event
from kestrel.dashboard.boards import create_dashboard
from kestrel.dashboard.presets import BOARD_TEMPLATES
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Severity
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.db.models.ticket import FindingTicket
from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus, WebhookEndpoint
from kestrel.demo import DEMO_INSTANCE_MARKER
from kestrel.demo.personas import DEFAULT_SEED
from kestrel.findings.investigation.status import create_finding_exception
from kestrel.findings.notes import add_note
from kestrel.findings.presets import FindingPresetError, create_or_update_preset
from kestrel.findings.watchers import watch_finding
from kestrel.policies.llm_settings import upsert_org_llm_settings

TREND_DAYS = 90

_NOTE_BODIES = (
    "Confirmed with the platform team — this is expected during the migration.",
    "Reached out to the owner; awaiting confirmation before we revoke.",
    "Duplicate of the access review item from last quarter.",
    "This one is real. Escalating to the on-call security engineer.",
    "Owner says the integration breaks without it. Needs a compensating control.",
    "Verified remediated in the provider console; waiting for the next sync.",
    "Tracking under the Q3 least-privilege initiative.",
    "Blocked on the vendor — they do not support scoped tokens yet.",
)

_EXCEPTION_REASONS = (
    "Break-glass account, reviewed quarterly by the security team.",
    "Vendor integration requires this scope; compensating control in place.",
    "Accepted risk through end of the migration (see RISK-114).",
    "Service account owned by Platform; rotation automated.",
    "False positive — the account is a shared mailbox, not a human.",
)

_MUTE_REASONS = (
    "Muted until the Q4 access review.",
    "Waiting on the vendor's scoped-token release.",
    "Known during migration; revisit after cutover.",
)

_SEED_OPERATORS = (
    ("nadia.okafor@acme.example.com", "Nadia Okafor", OperatorRole.ADMIN, True),
    ("omar.haddad@acme.example.com", "Omar Haddad", OperatorRole.ANALYST, True),
    ("priya.nair@acme.example.com", "Priya Nair", OperatorRole.ANALYST, True),
    ("ravi.iyer@acme.example.com", "Ravi Iyer", OperatorRole.READ_ONLY, True),
    ("sofia.moreno@acme.example.com", "Sofia Moreno", OperatorRole.ANALYST, False),
)

_AUDIT_ACTIONS = (
    ("finding.status_changed", "finding"),
    ("finding.assigned", "finding"),
    ("finding.note_added", "finding"),
    ("finding.exception_created", "finding"),
    ("policy.enabled", "policy"),
    ("policy.updated", "policy"),
    ("connector_instance.sync_requested", "connector_instance"),
    ("connector_instance.updated", "connector_instance"),
    ("webhook.created", "webhook_endpoint"),
    ("auth.login_succeeded", "operator"),
)


@dataclass
class ProductSeedResult:
    created: dict[str, int] = field(default_factory=dict)
    # Families deliberately not seeded, with the reason, so `demo up` can say so
    # instead of leaving the operator to wonder why a page is empty.
    skipped: list[str] = field(default_factory=list)

    def add(self, table: str, count: int) -> None:
        if count:
            self.created[table] = self.created.get(table, 0) + count

    @property
    def total(self) -> int:
        return sum(self.created.values())


def _operators(session: Session, org: Organization, result: ProductSeedResult, *, password: str | None) -> list[Operator]:
    """The admin created by `demo up` plus a small team around it.

    One operator makes assignment queues, the RBAC 403 banners, and the schedule
    recipient picker undemonstrable. ``password`` is the shared login for the
    seeded accounts in a local checkout; ``None`` (every deployment) leaves
    them without a password, so they populate pickers and audit history but
    nobody can sign in as them.
    """
    from kestrel.auth.passwords import hash_password

    existing = list(session.scalars(select(Operator).where(Operator.org_id == org.id)).all())
    by_email = {op.email: op for op in existing}
    created = 0
    for email, display_name, role, is_active in _SEED_OPERATORS:
        if email in by_email:
            continue
        operator = Operator(
            id=uuid.uuid4(),
            org_id=org.id,
            email=email,
            display_name=display_name,
            role=role,
            is_active=is_active,
            password_hash=hash_password(password) if password else None,
        )
        session.add(operator)
        existing.append(operator)
        created += 1
    session.flush()
    result.add("operators", created)
    return existing


def _triage_findings(
    session: Session,
    org: Organization,
    operators: list[Operator],
    result: ProductSeedResult,
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    """Spread findings across every status, owner, and mute state.

    A demo where all 250 findings are `open` and unassigned makes the status
    pie a single slice, four filter chips dead, and "My open findings"
    permanently empty -- all of which read as broken features rather than as an
    empty tenant.
    """
    findings = list(session.scalars(select(Finding).where(Finding.org_id == org.id).order_by(Finding.id)).all())
    if not findings:
        return

    actors = [op for op in operators if op.is_active]
    resolved = suppressed = excepted = muted = assigned = 0

    for finding in findings:
        roll = rng.random()
        if roll < 0.12:
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now - timedelta(days=rng.randint(1, 60))
            resolved += 1
        elif roll < 0.17:
            finding.status = FindingStatus.SUPPRESSED
            suppressed += 1
        elif roll < 0.21:
            finding.status = FindingStatus.MUTED
            # A few expire within the week so the mute-expiry queue is not empty.
            finding.muted_until = now + timedelta(days=rng.choice([2, 5, 30, 60]))
            finding.mute_reason = rng.choice(_MUTE_REASONS)
            muted += 1

        if finding.status is FindingStatus.OPEN and rng.random() < 0.4 and actors:
            finding.assigned_to_operator_id = rng.choice(actors).id
            assigned += 1

    result.add("findings.resolved", resolved)
    result.add("findings.suppressed", suppressed)
    result.add("findings.muted", muted)
    result.add("findings.assigned", assigned)

    # Notes, watchers, and exceptions on the most severe open findings -- the
    # ones an operator would actually have worked.
    severe = [f for f in findings if f.status is FindingStatus.OPEN and f.severity in {Severity.CRITICAL, Severity.HIGH}]
    rng.shuffle(severe)

    notes = watchers = 0
    for finding in severe[:14]:
        for _ in range(rng.randint(1, 3)):
            add_note(
                session,
                finding=finding,
                author_operator_id=rng.choice(actors).id,
                body=rng.choice(_NOTE_BODIES),
            )
            notes += 1
    for finding in severe[:18]:
        watch_finding(session, org_id=org.id, operator_id=rng.choice(actors).id, finding=finding)
        watchers += 1

    for finding in severe[18:28]:
        expires = rng.choice([None, now + timedelta(days=4), now + timedelta(days=45), now + timedelta(days=120)])
        create_finding_exception(
            session,
            finding=finding,
            reason=rng.choice(_EXCEPTION_REASONS),
            created_by_operator_id=rng.choice(actors).id,
            expires_at=expires,
        )
        excepted += 1

    session.flush()
    result.add("finding_notes", notes)
    result.add("finding_watchers", watchers)
    result.add("exceptions", excepted)


def _webhooks(
    session: Session,
    org: Organization,
    result: ProductSeedResult,
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    from kestrel.secrets.crypto import MissingMasterKeyError
    from kestrel.webhooks.authoring import WebhookAuthoringError, create_endpoint

    # `create_endpoint` runs the real SSRF check, which resolves the host. That
    # is the right behaviour for a product endpoint and the wrong thing to make
    # `demo up` depend on, so use hosts that actually resolve (example.com is
    # IANA-reserved for exactly this) and tolerate failure on an offline machine.
    existing = {
        endpoint.name: endpoint
        for endpoint in session.scalars(select(WebhookEndpoint).where(WebhookEndpoint.org_id == org.id)).all()
    }
    endpoints = []
    created_any = False
    for name, url, events in (
        ("SIEM forwarder", "https://example.com/hooks/kestrel", ["finding.opened", "finding.resolved"]),
        ("PagerDuty critical", "https://example.com/pagerduty", ["finding.opened"]),
        ("Audit archive", "https://example.com/archive", ["finding.resolved"]),
    ):
        if name in existing:
            # Seeded by an earlier `demo up`; `demo down` keeps operator-side data.
            endpoints.append(existing[name])
            continue
        created_any = True
        try:
            endpoint, _secret = create_endpoint(session, org_id=org.id, name=name, url=url, events=events)
        except (WebhookAuthoringError, MissingMasterKeyError):
            # The SSRF check could not resolve the host (offline), or there is
            # no master key to encrypt the signing secret with.
            continue
        endpoints.append(endpoint)
    # Disabled, so later syncs and `demo change` never queue real deliveries
    # to example.com: the seeded history below is the only traffic they show.
    # Re-applied to endpoints from an earlier `demo up`, which were enabled.
    for endpoint in endpoints:
        endpoint.is_enabled = False
    session.flush()
    result.add("webhook_endpoints", len(endpoints))
    if not endpoints:
        result.skipped.append("webhook endpoints (URL validation could not resolve a host)")
        return
    if not created_any:
        result.skipped.append("webhook endpoints and deliveries (already seeded)")
        return

    findings = list(session.scalars(select(Finding).where(Finding.org_id == org.id).limit(60)).all())
    deliveries = 0
    for _index in range(50):
        endpoint = rng.choice(endpoints)
        finding = rng.choice(findings) if findings else None
        roll = rng.random()
        if roll < 0.78:
            status, http_status, error, attempts = WebhookDeliveryStatus.SUCCESS, 200, None, 1
        elif roll < 0.94:
            status, http_status, error, attempts = (
                WebhookDeliveryStatus.FAILED,
                rng.choice([500, 502, 504]),
                "upstream returned an error",
                rng.randint(2, 3),
            )
        else:
            status, http_status, error, attempts = WebhookDeliveryStatus.PENDING, None, None, 0
        created = now - timedelta(days=rng.randint(0, 30), minutes=rng.randint(0, 1440))
        session.add(
            WebhookDelivery(
                id=uuid.uuid4(),
                org_id=org.id,
                webhook_endpoint_id=endpoint.id,
                finding_id=finding.id if finding else None,
                event_type="finding.opened",
                payload={"event": "finding.opened", "finding_id": str(finding.id) if finding else None},
                status=status,
                attempt_count=attempts,
                http_status=http_status,
                error_message=error,
                created_at=created,
                delivered_at=created + timedelta(seconds=2) if status is WebhookDeliveryStatus.SUCCESS else None,
            )
        )
        deliveries += 1
    session.flush()
    result.add("webhook_deliveries", deliveries)


def _ticketing(
    session: Session,
    org: Organization,
    operators: list[Operator],
    result: ProductSeedResult,
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    from kestrel.secrets.crypto import MissingMasterKeyError
    from kestrel.ticketing.authoring import TicketAuthoringError, create_integration

    integrations = []
    for name, provider, config in (
        (
            "Acme GitHub Issues",
            "github_issues",
            {"repo": "acme-corp/security-findings"},
        ),
        (
            "Acme Jira",
            "jira_cloud",
            {
                "base_url": "https://example.com",
                "project_key": "SEC",
                "email": "security@acme.example.com",
            },
        ),
    ):
        try:
            integrations.append(
                create_integration(
                    session,
                    org_id=org.id,
                    name=name,
                    provider=provider,
                    api_token="demo-token-not-a-real-credential",
                    config=config,
                )
            )
        except (TicketAuthoringError, MissingMasterKeyError) as exc:
            # One bad provider config should not take the whole seed down, but
            # it must not vanish either -- a silently missing integration looks
            # identical to a broken settings page.
            result.skipped.append(f"ticket integration {name!r}: {exc}")
            continue
    session.flush()
    result.add("ticket_integrations", len(integrations))
    if not integrations:
        return

    # Constructed directly: `create_ticket_for_finding` posts to the live
    # tracker, and its dry-run mode writes nothing.
    findings = list(
        session.scalars(
            select(Finding).where(Finding.org_id == org.id, Finding.severity == Severity.CRITICAL).limit(10)
        ).all()
    )
    tickets = 0
    for index, finding in enumerate(findings):
        integration = integrations[index % len(integrations)]
        if integration.provider == "github_issues":
            external_id, url = f"{2100 + index}", f"https://github.com/acme-corp/security-findings/issues/{2100 + index}"
        else:
            external_id, url = f"SEC-{400 + index}", f"https://example.com/browse/SEC-{400 + index}"
        session.add(
            FindingTicket(
                id=uuid.uuid4(),
                org_id=org.id,
                finding_id=finding.id,
                ticket_integration_id=integration.id,
                provider=integration.provider,
                external_id=external_id,
                url=url,
                created_by_operator_id=rng.choice(operators).id,
                created_at=now - timedelta(days=rng.randint(1, 40)),
            )
        )
        tickets += 1
    session.flush()
    result.add("finding_tickets", tickets)


def _posture_trend(
    session: Session,
    org: Organization,
    result: ProductSeedResult,
    *,
    rng: random.Random,
    today: date,
) -> None:
    """A 90-day trend curve ending at today's real counts.

    Written directly rather than through `capture_posture_snapshot`, which
    recomputes from current state -- calling it ninety times with different
    clocks produces ninety identical points and a flat line.
    """
    open_counts: dict[Severity, int] = {
        row[0]: int(row[1])
        for row in session.execute(
            select(Finding.severity, func.count())
            .where(Finding.org_id == org.id, Finding.status == FindingStatus.OPEN)
            .group_by(Finding.severity)
        ).all()
    }
    today_counts = {severity.value: open_counts.get(severity, 0) for severity in Severity}

    existing = set(
        session.scalars(select(PostureTrendSnapshot.snapshot_date).where(PostureTrendSnapshot.org_id == org.id)).all()
    )

    written = 0
    for days_ago in range(TREND_DAYS, -1, -1):
        snapshot_date = today - timedelta(days=days_ago)
        if snapshot_date in existing:
            continue
        # Walk backwards from today's real numbers with a gentle upward drift
        # into the past plus noise, so the line moves without being random.
        scale = 1.0 + (days_ago / TREND_DAYS) * 0.45
        counts = {
            severity: max(0, round(value * scale * rng.uniform(0.92, 1.08))) for severity, value in today_counts.items()
        }
        attention = counts.get("critical", 0) + counts.get("high", 0)
        session.add(
            PostureTrendSnapshot(
                id=uuid.uuid4(),
                org_id=org.id,
                snapshot_date=snapshot_date,
                open_by_severity=counts,
                factor_counts={
                    "privileged_without_mfa": max(0, counts.get("critical", 0) - 1),
                    "external_privileged": max(0, counts.get("high", 0) // 4),
                    "dormant_privileged": max(0, counts.get("medium", 0) // 5),
                },
                attention_count=attention,
            )
        )
        written += 1
    session.flush()
    result.add("posture_trend_snapshots", written)


def _dashboards(
    session: Session,
    org: Organization,
    operators: list[Operator],
    result: ProductSeedResult,
) -> None:
    """Boards beyond the default Home.

    `BOARD_TEMPLATES` ships three and nothing ever instantiated them, so a
    freshly seeded demo had exactly one dashboard and the multi-board nav,
    the per-application boards, and the private-vs-org visibility split were
    all undemonstrable.
    """
    admin = next((o for o in operators if o.role == OperatorRole.ADMIN), operators[0])
    analyst = next((o for o in operators if o.role == OperatorRole.ANALYST), admin)
    created = 0
    for template in BOARD_TEMPLATES:
        # Exec boards belong to the admin; per-application boards read more
        # naturally as an analyst's own working view.
        owner = admin if template["slug"] == "exec-weekly" else analyst
        try:
            create_dashboard(
                session,
                org_id=org.id,
                operator=owner,
                name=str(template["name"]),
                slug=str(template["slug"]),
                description=template.get("description"),
                template=str(template["slug"]),
            )
            created += 1
        except ValueError:
            # Slug already there from an earlier run; the seed is re-runnable.
            continue
    result.add("dashboards", created)


def _finding_presets(
    session: Session,
    org: Organization,
    operators: list[Operator],
    result: ProductSeedResult,
) -> None:
    """Saved searches, so the Findings favourites row is not an empty shelf.

    Keys must be in `presets.ALLOWED_FILTER_KEYS` -- the stored filters are
    replayed as query parameters against the listing, so there is no free-text
    shorthand here.
    """
    admin = next((o for o in operators if o.role == OperatorRole.ADMIN), operators[0])
    presets: tuple[tuple[str, dict], ...] = (
        ("Critical and open", {"severity": "critical", "status": "open"}),
        ("My queue", {"status": "open", "assigned_to_operator_id": str(admin.id)}),
        ("Unowned", {"status": "open", "unassigned": True}),
        ("Ageing over 7 days", {"status": "open", "open_older_than_days": 7}),
    )
    created = 0
    for name, filters in presets:
        try:
            create_or_update_preset(session, org_id=org.id, operator_id=admin.id, name=name, filters=filters)
            created += 1
        except FindingPresetError:
            # A filter the listing no longer accepts is the seed's problem to
            # fix, not the operator's to see as a failed `demo up`.
            continue
    result.add("finding_filter_presets", created)


def _llm_settings(session: Session, org: Organization, result: ProductSeedResult) -> None:
    """Settings -> AI reads "configured" rather than "not configured".

    A placeholder key, deliberately invalid: the policy workbench's AI draft
    path resolves org settings first, and a demo should show the wiring
    without implying a live model is reachable.
    """
    upsert_org_llm_settings(
        session,
        org_id=org.id,
        provider="anthropic",
        api_key="sk-ant-demo-placeholder-not-a-real-key",
        is_enabled=False,
    )
    result.add("org_llm_settings", 1)


# One schedule per connector, staggered so the Integrations list does not read
# as four instances configured by a script in the same minute.
_DEMO_SCHEDULES = ("0 */6 * * *", "30 2,14 * * *", "0 3 * * *", "15 */12 * * *")


def _connector_history(
    session: Session,
    org: Organization,
    result: ProductSeedResult,
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    """Backfill run history and set schedules on the demo instances.

    `demo up` syncs each tenant once, so every connector showed exactly one
    run and "manual" for its schedule. The run-history table, the health
    center's degraded state, and the schedule column were all unexercised --
    and a fleet where nothing has ever partially failed misrepresents what
    operating this actually looks like.

    The prior runs are history only: no entities, no events, no findings hang
    off them, so this cannot disturb the Changes timeline.
    """
    instances = list(
        session.scalars(
            select(ConnectorInstance)
            .join(ApplicationInstance, ApplicationInstance.id == ConnectorInstance.application_instance_id)
            .where(
                ConnectorInstance.org_id == org.id,
                ApplicationInstance.display_name.contains(DEMO_INSTANCE_MARKER),
            )
            .order_by(ConnectorInstance.created_at)
        ).all()
    )
    if not instances:
        result.skipped.append("connector run history (no demo connector instances yet)")
        return

    runs = 0
    scheduled = 0
    for index, instance in enumerate(instances):
        if not instance.schedule_cron:
            instance.schedule_cron = _DEMO_SCHEDULES[index % len(_DEMO_SCHEDULES)]
            scheduled += 1

        existing = (
            session.scalar(
                select(func.count()).select_from(ConnectorRun).where(ConnectorRun.connector_instance_id == instance.id)
            )
            or 0
        )
        if existing > 1:
            continue  # history already backfilled; keep `demo up` re-runnable

        # Fourteen days of twice-daily scheduled runs, ending before the
        # real run `demo up` created so the newest row stays the live one.
        for step in range(1, 15):
            started = now - timedelta(days=step, hours=rng.randint(0, 6))
            status = ConnectorRunStatus.SUCCESS
            error = None
            skipped: dict = {}
            roll = rng.random()
            if roll < 0.12:
                status = ConnectorRunStatus.PARTIAL_FAILURE
                skipped = {"audit_log": "not available on this plan"}
            elif roll < 0.18:
                status = ConnectorRunStatus.FAILED
                error = "429 Too Many Requests from the provider; retried and gave up"
            session.add(
                ConnectorRun(
                    id=uuid.uuid4(),
                    org_id=org.id,
                    connector_instance_id=instance.id,
                    status=status,
                    started_at=started,
                    finished_at=started + timedelta(seconds=rng.randint(20, 240)),
                    object_counts={} if status is ConnectorRunStatus.FAILED else {"identity": rng.randint(40, 320)},
                    skipped_object_types=skipped,
                    error_summary=error,
                    triggered_by=ConnectorRunTrigger.SCHEDULE,
                )
            )
            runs += 1

    session.flush()
    result.add("connector_runs", runs)
    result.add("connector_schedules", scheduled)


def _audit_log(
    session: Session,
    org: Organization,
    operators: list[Operator],
    result: ProductSeedResult,
    *,
    rng: random.Random,
    now: datetime,
) -> None:
    """Audit history, which also fills the finding-detail activity timeline.

    That timeline reads `audit_log` rows targeting the finding; with none, every
    finding shows a single synthetic "detected" row.
    """
    findings = list(session.scalars(select(Finding).where(Finding.org_id == org.id).limit(80)).all())
    rows = 0
    for index in range(300):
        action, target_type = _AUDIT_ACTIONS[index % len(_AUDIT_ACTIONS)]
        target_id = None
        if target_type == "finding" and findings:
            target_id = rng.choice(findings).id
        event = record_audit_event(
            session,
            org_id=org.id,
            actor_operator_id=rng.choice(operators).id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            context={"source": "demo-seed"},
        )
        # `record_audit_event` stamps `created_at` from the server clock; the
        # audit page and the finding timeline both order by it, so a seed with
        # 300 rows at one instant is useless for either.
        event.created_at = now - timedelta(days=rng.randint(0, 89), minutes=rng.randint(0, 1440))
        rows += 1
    session.flush()
    result.add("audit_log", rows)


def seed_product_data(
    session: Session,
    org: Organization,
    *,
    seed: int = DEFAULT_SEED,
    now: datetime | None = None,
    operator_password: str | None = None,
) -> ProductSeedResult:
    """Populate the operator-side tables. Idempotent enough to re-run.

    ``operator_password`` is given to the seeded team accounts; leave it
    ``None`` anywhere reachable from a network so they cannot be used to log in.
    """
    clock = now or datetime.now(UTC)
    rng = random.Random(seed + 7)
    result = ProductSeedResult()

    operators = _operators(session, org, result, password=operator_password)
    _triage_findings(session, org, operators, result, rng=rng, now=clock)
    _dashboards(session, org, operators, result)
    _finding_presets(session, org, operators, result)

    # Webhook endpoints and ticket integrations store an encrypted secret, so
    # they need KESTREL_MASTER_KEY. Nothing loads `.env` into the process for a
    # bare `kestrel demo up`, so treat the key as optional enrichment: skipping
    # two settings pages is far better than failing the whole seed.
    if _master_key_available():
        _webhooks(session, org, result, rng=rng, now=clock)
        _ticketing(session, org, operators, result, rng=rng, now=clock)
        _llm_settings(session, org, result)
    else:
        result.skipped.append("webhooks, ticketing, and AI settings (set KESTREL_MASTER_KEY to seed them)")

    _connector_history(session, org, result, rng=rng, now=clock)
    _posture_trend(session, org, result, rng=rng, today=clock.date())
    _audit_log(session, org, operators, result, rng=rng, now=clock)
    return result


def _master_key_available() -> bool:
    from kestrel.secrets.crypto import EnvKeyProvider, MissingMasterKeyError

    try:
        EnvKeyProvider()
    except (MissingMasterKeyError, ValueError):  # unset, or not valid base64
        return False
    return True
