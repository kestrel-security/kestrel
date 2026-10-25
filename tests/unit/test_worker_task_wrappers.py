# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The Celery task wrappers' transaction handling, without a broker or a
database: each wraps one domain call, and what it owes the caller is a commit
on success, a rollback on failure, a closed session either way, and webhook
deliveries enqueued only after the commit that created them."""

from __future__ import annotations

# The Celery app registers every task module on import; importing a task
# module before it re-enters that registration half-initialized.
import kestrel_worker.celery_app  # noqa: F401  (isort: skip)
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest
from kestrel.findings.lifecycle import ReopenResult
from kestrel.notifications.email_transport import EmailResult
from kestrel.webhooks.delivery import WebhookDeliveryError
from kestrel_worker.tasks import dashboard_schedules as dashboard_task
from kestrel_worker.tasks import evaluate as evaluate_task
from kestrel_worker.tasks import finding_lifecycle as lifecycle_task
from kestrel_worker.tasks import notifications as notifications_task
from kestrel_worker.tasks import posture_trend as posture_task
from kestrel_worker.tasks import webhooks as webhooks_task

_ORG = "00000000-0000-0000-0000-000000000001"


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


@dataclass
class _FakeSession:
    """Records the transaction calls a task makes, in order."""

    org_ids: list[uuid.UUID] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def scalars(self, _stmt: Any) -> _Scalars:
        return _Scalars(self.org_ids)

    def commit(self) -> None:
        self.calls.append("commit")

    def rollback(self) -> None:
        self.calls.append("rollback")

    def close(self) -> None:
        self.calls.append("close")


@dataclass
class _Delays:
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


def _bind_session(monkeypatch: pytest.MonkeyPatch, module: Any, session: _FakeSession) -> None:
    monkeypatch.setattr(module, "get_sessionmaker", lambda: lambda: session)


def _capture_webhook_delays(monkeypatch: pytest.MonkeyPatch, module: Any) -> _Delays:
    delays = _Delays()
    monkeypatch.setattr(module.deliver_webhook, "delay", delays)
    return delays


# --- evaluate_policies -------------------------------------------------------


def test_evaluate_commits_then_enqueues_each_webhook_and_returns_the_evaluation_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, evaluate_task, session)
    delays = _capture_webhook_delays(monkeypatch, evaluate_task)
    org_id, run_id = uuid.uuid4(), uuid.uuid4()
    delivery_ids = [uuid.uuid4(), uuid.uuid4()]
    seen: dict[str, Any] = {}

    def fake_evaluate(sess, *, org_id, connector_run_id, webhook_delivery_ids):
        seen.update(org_id=org_id, connector_run_id=connector_run_id)
        assert sess is session
        # Enqueuing happens after commit, so nothing has been delayed yet.
        assert delays.calls == []
        webhook_delivery_ids.extend(delivery_ids)
        return ["e1", "e2", "e3"]

    monkeypatch.setattr(evaluate_task, "evaluate_all_enabled_policies", fake_evaluate)

    result = evaluate_task.evaluate_policies.run(org_id=str(org_id), connector_run_id=str(run_id))

    assert result == 3
    assert seen == {"org_id": org_id, "connector_run_id": run_id}
    assert session.calls == ["commit", "close"]
    assert delays.calls == [{"delivery_id": str(d)} for d in delivery_ids]


def test_evaluate_without_a_run_id_passes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, evaluate_task, session)
    _capture_webhook_delays(monkeypatch, evaluate_task)
    seen: dict[str, Any] = {}

    def fake_evaluate(_sess, *, org_id, connector_run_id, webhook_delivery_ids):
        seen["connector_run_id"] = connector_run_id
        return []

    monkeypatch.setattr(evaluate_task, "evaluate_all_enabled_policies", fake_evaluate)

    assert evaluate_task.evaluate_policies.run(org_id=str(uuid.uuid4())) == 0
    assert seen == {"connector_run_id": None}


def test_evaluate_failure_rolls_back_closes_and_enqueues_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, evaluate_task, session)
    delays = _capture_webhook_delays(monkeypatch, evaluate_task)

    def failing(_sess, *, webhook_delivery_ids, **_kwargs):
        webhook_delivery_ids.append(uuid.uuid4())
        raise RuntimeError("policy runtime crashed")

    monkeypatch.setattr(evaluate_task, "evaluate_all_enabled_policies", failing)

    with pytest.raises(RuntimeError, match="policy runtime crashed"):
        evaluate_task.evaluate_policies.run(org_id=str(uuid.uuid4()))

    assert session.calls == ["rollback", "close"]
    assert delays.calls == []


# --- deliver_webhook ---------------------------------------------------------


def test_deliver_webhook_success_commits_and_returns_the_status_value(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel.db.models.webhook import WebhookDeliveryStatus

    session = _FakeSession()
    _bind_session(monkeypatch, webhooks_task, session)
    delivery_id = uuid.uuid4()
    seen: list[uuid.UUID] = []

    class _Delivery:
        status = WebhookDeliveryStatus.SUCCESS

    def fake_deliver(_sess, did):
        seen.append(did)
        return _Delivery()

    monkeypatch.setattr(webhooks_task, "deliver_webhook_delivery", fake_deliver)

    assert webhooks_task.deliver_webhook.run(delivery_id=str(delivery_id)) == WebhookDeliveryStatus.SUCCESS.value
    assert seen == [delivery_id]
    assert session.calls == ["commit", "close"]


def test_deliver_webhook_failure_persists_the_attempt_before_retrying(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, webhooks_task, session)

    def failing(_sess, _did):
        raise WebhookDeliveryError("endpoint returned 503")

    monkeypatch.setattr(webhooks_task, "deliver_webhook_delivery", failing)
    retries: list[tuple[BaseException, int]] = []

    def fake_retry(*, exc, countdown):
        retries.append((exc, countdown))
        return RuntimeError("retry scheduled")

    monkeypatch.setattr(webhooks_task.deliver_webhook, "retry", fake_retry)

    with pytest.raises(RuntimeError, match="retry scheduled"):
        webhooks_task.deliver_webhook.run(delivery_id=str(uuid.uuid4()))

    # Committed, not rolled back: the failed attempt's count and error must stick.
    assert session.calls == ["commit", "close"]
    assert len(retries) == 1
    assert isinstance(retries[0][0], WebhookDeliveryError)
    assert retries[0][1] == 30  # first retry; doubles from here


def test_deliver_webhook_permanent_failure_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A disabled endpoint, a rejected URL or a 4xx answers the same way next
    time; the row already says FAILED, so the task ends instead of retrying."""
    session = _FakeSession()
    _bind_session(monkeypatch, webhooks_task, session)

    def failing(_sess, _did):
        raise WebhookDeliveryError("HTTP 410: gone", permanent=True)

    monkeypatch.setattr(webhooks_task, "deliver_webhook_delivery", failing)

    def never_retry(**_kwargs):
        raise AssertionError("permanent failures must not be retried")

    monkeypatch.setattr(webhooks_task.deliver_webhook, "retry", never_retry)

    assert webhooks_task.deliver_webhook.run(delivery_id=str(uuid.uuid4())) == "failed"
    assert session.calls == ["commit", "close"]


def test_deliver_webhook_unexpected_error_rolls_back_and_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, webhooks_task, session)

    def failing(_sess, _did):
        raise LookupError("delivery row vanished")

    monkeypatch.setattr(webhooks_task, "deliver_webhook_delivery", failing)

    with pytest.raises(LookupError):
        webhooks_task.deliver_webhook.run(delivery_id=str(uuid.uuid4()))

    assert session.calls == ["rollback", "close"]


def test_deliver_webhook_retry_budget_is_bounded() -> None:
    assert webhooks_task.deliver_webhook.max_retries == 5
    assert webhooks_task.deliver_webhook.default_retry_delay > 0


# --- capture_daily_posture_snapshots -----------------------------------------


def test_posture_capture_isolates_a_failing_org(monkeypatch: pytest.MonkeyPatch) -> None:
    good_a, bad, good_b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    session = _FakeSession(org_ids=[good_a, bad, good_b])
    _bind_session(monkeypatch, posture_task, session)
    captured: list[uuid.UUID] = []

    def fake_capture(_sess, org_id):
        if org_id == bad:
            raise ValueError("scorecard failed")
        captured.append(org_id)

    monkeypatch.setattr(posture_task, "capture_posture_snapshot", fake_capture)

    assert posture_task.capture_daily_posture_snapshots.run() == 2
    assert captured == [good_a, good_b]
    assert session.calls == ["commit", "rollback", "commit", "close"]


def test_posture_capture_with_no_orgs_captures_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, posture_task, session)
    monkeypatch.setattr(posture_task, "capture_posture_snapshot", lambda *_: pytest.fail("no org to capture"))

    assert posture_task.capture_daily_posture_snapshots.run() == 0
    assert session.calls == ["close"]


# --- reopen_expired_finding_deferrals ----------------------------------------


def test_reopen_sweep_locks_each_org_sums_reopens_and_enqueues_after_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = uuid.uuid4(), uuid.uuid4()
    session = _FakeSession(org_ids=[first, second])
    _bind_session(monkeypatch, lifecycle_task, session)
    delays = _capture_webhook_delays(monkeypatch, lifecycle_task)
    locks: list[tuple[uuid.UUID, Any]] = []
    monkeypatch.setattr(lifecycle_task, "org_advisory_xact_lock", lambda _s, org_id, key: locks.append((org_id, key)))
    delivery = uuid.uuid4()

    def fake_reopen(_sess, org_id, *, webhook_delivery_ids):
        if org_id == first:
            webhook_delivery_ids.append(delivery)
            return ReopenResult(mutes_reopened=[uuid.uuid4()], exceptions_reopened=[uuid.uuid4()])
        return ReopenResult(mutes_reopened=[uuid.uuid4()])

    monkeypatch.setattr(lifecycle_task, "reopen_expired_deferrals", fake_reopen)

    assert lifecycle_task.reopen_expired_finding_deferrals.run() == 3
    assert locks == [(first, lifecycle_task.POLICY_EVALUATION), (second, lifecycle_task.POLICY_EVALUATION)]
    assert session.calls == ["commit", "commit", "close"]
    assert delays.calls == [{"delivery_id": str(delivery)}]


def test_reopen_sweep_skips_a_failing_org_without_enqueuing_its_webhooks(monkeypatch: pytest.MonkeyPatch) -> None:
    bad, good = uuid.uuid4(), uuid.uuid4()
    session = _FakeSession(org_ids=[bad, good])
    _bind_session(monkeypatch, lifecycle_task, session)
    delays = _capture_webhook_delays(monkeypatch, lifecycle_task)
    monkeypatch.setattr(lifecycle_task, "org_advisory_xact_lock", lambda *_: None)

    def fake_reopen(_sess, org_id, *, webhook_delivery_ids):
        if org_id == bad:
            webhook_delivery_ids.append(uuid.uuid4())
            raise RuntimeError("lock timeout")
        return ReopenResult(exceptions_reopened=[uuid.uuid4()])

    monkeypatch.setattr(lifecycle_task, "reopen_expired_deferrals", fake_reopen)

    assert lifecycle_task.reopen_expired_finding_deferrals.run() == 1
    assert session.calls == ["rollback", "commit", "close"]
    assert delays.calls == []


# --- dashboard and notification dispatchers ----------------------------------


def test_dashboard_dispatch_returns_the_count_and_closes_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, dashboard_task, session)
    monkeypatch.setattr(dashboard_task, "dispatch_due_schedules", lambda sess: 4 if sess is session else -1)

    assert dashboard_task.dispatch_dashboard_schedules.run() == 4
    assert session.calls == ["close"]


def test_dashboard_dispatch_closes_the_session_when_dispatch_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, dashboard_task, session)

    def failing(_sess):
        raise RuntimeError("db down")

    monkeypatch.setattr(dashboard_task, "dispatch_due_schedules", failing)

    with pytest.raises(RuntimeError):
        dashboard_task.dispatch_dashboard_schedules.run()
    assert session.calls == ["close"]


def test_watch_digests_commit_the_sent_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, notifications_task, session)
    monkeypatch.setattr(notifications_task, "send_due_watch_digests", lambda _sess: 2)

    assert notifications_task.send_watch_digests.run() == 2
    assert session.calls == ["commit", "close"]


def test_watch_digests_do_not_commit_when_sending_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession()
    _bind_session(monkeypatch, notifications_task, session)

    def failing(_sess):
        raise RuntimeError("smtp exploded")

    monkeypatch.setattr(notifications_task, "send_due_watch_digests", failing)

    with pytest.raises(RuntimeError):
        notifications_task.send_watch_digests.run()
    assert session.calls == ["close"]


def test_send_emails_rebuilds_items_and_sends_one_email_per_recipient(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []

    class _Transport:
        def send(self, **kwargs: Any) -> EmailResult:
            sent.append(kwargs)
            return EmailResult(delivered=True, backend="smtp", detail=None)

    from kestrel.notifications import email as email_module

    monkeypatch.setattr(email_module, "_org_transport", lambda _org_id: _Transport())
    items = [
        {"org_id": _ORG, "to": "a@example.test", "title": "Finding opened", "body": None, "detail_path": "/findings/1"},
        {"org_id": _ORG, "to": "a@example.test", "title": "Finding resolved", "body": "done", "detail_path": None},
        {"org_id": _ORG, "to": "b@example.test", "title": "Finding opened", "body": None, "detail_path": None},
    ]

    assert notifications_task.send_emails.run(items) == 2
    assert sorted(call["to"][0] for call in sent) == ["a@example.test", "b@example.test"]


# --- schedule dispatch ledger selection and failure modes --------------------


def test_memory_backend_returns_one_process_wide_in_memory_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel_worker.tasks import schedule as schedule_task

    monkeypatch.setenv("KESTREL_SYNC_LOCK_BACKEND", " Memory ")
    monkeypatch.setattr(schedule_task, "_memory_ledger", None)

    first = schedule_task.get_dispatch_ledger()
    second = schedule_task.get_dispatch_ledger()

    assert isinstance(first, schedule_task.InMemoryDispatchLedger)
    assert first is second


def test_an_unusable_redis_url_falls_back_to_no_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel_worker.tasks import schedule as schedule_task

    monkeypatch.setenv("KESTREL_SYNC_LOCK_BACKEND", "redis")
    # No scheme: rejected while parsing, before any connection is attempted.
    monkeypatch.setenv("REDIS_URL", "not-a-redis-url")

    assert schedule_task.get_dispatch_ledger() is None


def test_the_redis_ledger_refuses_a_fire_another_dispatcher_claimed() -> None:
    from datetime import UTC, datetime

    from kestrel_worker.tasks.schedule import RedisDispatchLedger

    class _Client:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}

        def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
            if nx and key in self.values:
                return False
            self.values[key] = value
            return True

        def get(self, key: str) -> bytes | None:
            value = self.values.get(key)
            return value.encode() if value is not None else None

    ledger = RedisDispatchLedger(_Client())
    fire = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)

    assert ledger.claim("i", fire) is True
    assert ledger.claim("i", fire) is False
    # Bytes from a client without decode_responses are decoded.
    assert ledger.last_fire("i") == fire


def test_the_in_memory_ledger_keeps_the_latest_fire_when_an_older_one_is_claimed() -> None:
    from datetime import UTC, datetime

    from kestrel_worker.tasks.schedule import InMemoryDispatchLedger

    ledger = InMemoryDispatchLedger()
    later = datetime(2026, 3, 1, 10, 0, tzinfo=UTC)
    earlier = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)

    assert ledger.claim("i", later) is True
    assert ledger.claim("i", earlier) is True
    assert ledger.last_fire("i") == later


def test_a_claim_that_errors_after_a_good_read_still_dispatches() -> None:
    from datetime import UTC, datetime

    from kestrel_worker.tasks.schedule import claim_due_fire
    from redis.exceptions import RedisError

    class _ClaimFails:
        def last_fire(self, instance_id: str) -> datetime | None:
            return None

        def claim(self, instance_id: str, fire: datetime) -> bool:
            raise RedisError("connection reset")

    now = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
    assert claim_due_fire("0 9 * * *", now=now, instance_id="i", ledger=_ClaimFails()) == now
