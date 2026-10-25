# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- webhook signing and delivery (``webhooks.signing`` /
``webhooks.delivery`` / ``webhooks.dispatch``).

Delivery goes through the ``http_client=`` seam ``webhooks/delivery.py``
already accepts (an ``httpx.Client`` built on ``httpx.MockTransport``) --
never a real network request. The endpoint URL still has to pass the SSRF
guard in ``security.ssrf``, which rejects private/loopback literals, so
tests use an https URL on a public IP literal (``8.8.8.8``) that the SSRF check accepts
without any DNS lookup, then never actually contact it because the mock
transport intercepts the call.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion, Severity
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED, WebhookDelivery, WebhookDeliveryStatus
from kestrel.testing import make_organization
from kestrel.webhooks.authoring import create_endpoint, decrypt_endpoint_secret
from kestrel.webhooks.delivery import WebhookDeliveryError, deliver_webhook_delivery
from kestrel.webhooks.dispatch import schedule_finding_webhooks
from kestrel.webhooks.signing import sign_payload, verify_signature
from sqlalchemy import select
from sqlalchemy.orm import Session

_SAFE_URL = "https://8.8.8.8/hook"  # public IP literal: passes the SSRF guard with no DNS lookup


def test_sign_and_verify_signature_roundtrip():
    secret = "whsec_test_secret"
    body = json.dumps({"hello": "world"}).encode("utf-8")

    signature, timestamp = sign_payload(secret=secret, body=body)

    assert signature.startswith("v1=")
    assert verify_signature(secret=secret, body=body, signature_header=signature, timestamp=timestamp)


def test_verify_signature_rejects_wrong_secret():
    body = b'{"a":1}'
    signature, timestamp = sign_payload(secret="secret-a", body=body)
    assert not verify_signature(secret="secret-b", body=body, signature_header=signature, timestamp=timestamp)


def test_verify_signature_rejects_stale_timestamp():
    body = b'{"a":1}'
    secret = "whsec_test"
    signature, timestamp = sign_payload(secret=secret, body=body)

    # 10 minutes later, outside the default 5-minute tolerance.
    assert not verify_signature(
        secret=secret, body=body, signature_header=signature, timestamp=timestamp, now=timestamp + 600
    )


def _make_finding(session: Session, org) -> Finding:
    from datetime import UTC, datetime

    from kestrel.db.models.policy import PolicyEvaluation, PolicyEvaluationStatus

    policy = Policy(
        id=uuid.uuid4(), org_id=org.id, slug=f"p-{uuid.uuid4().hex[:8]}", title="Policy", source=PolicySource.CUSTOM
    )
    session.add(policy)
    session.flush()
    version = PolicyVersion(
        id=uuid.uuid4(), policy_id=policy.id, version=1, source_text="", severity=Severity.HIGH, compliance_mappings={}
    )
    session.add(version)
    session.flush()
    policy.current_version_id = version.id

    evaluation = PolicyEvaluation(
        id=uuid.uuid4(),
        org_id=org.id,
        policy_version_id=version.id,
        started_at=datetime.now(UTC),
        status=PolicyEvaluationStatus.SUCCESS,
    )
    session.add(evaluation)
    session.flush()

    finding = Finding(
        id=uuid.uuid4(),
        org_id=org.id,
        policy_version_id=version.id,
        policy_evaluation_id=evaluation.id,
        title="Test finding",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        first_seen_at=datetime.now(UTC),
        last_seen_at=datetime.now(UTC),
        subject_type=FindingSubjectType.IDENTITY,
        subject_id=uuid.uuid4(),
    )
    session.add(finding)
    session.flush()
    return finding


def test_deliver_webhook_delivery_success_signs_and_records_status(db_session: Session):
    org = make_organization(db_session)
    endpoint, secret = create_endpoint(
        db_session, org_id=org.id, name="Test endpoint", url=_SAFE_URL, events=[FINDING_OPENED]
    )
    finding = _make_finding(db_session, org)

    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"ok": True})

    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        finding_id=finding.id,
        event_type=FINDING_OPENED,
        payload={"type": FINDING_OPENED, "data": {"finding": {"id": str(finding.id)}}},
        status=WebhookDeliveryStatus.PENDING,
        attempt_count=0,
    )
    db_session.add(delivery)
    db_session.flush()

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    assert result.status is WebhookDeliveryStatus.SUCCESS
    assert result.http_status == 200
    assert result.attempt_count == 1

    request = captured["request"]
    body = request.content
    signature = request.headers["X-Kestrel-Signature"]
    timestamp = int(request.headers["X-Kestrel-Timestamp"])
    assert verify_signature(secret=secret, body=body, signature_header=signature, timestamp=timestamp)


def test_deliver_webhook_delivery_marks_failed_on_non_2xx(db_session: Session):
    org = make_organization(db_session)
    endpoint, _secret = create_endpoint(
        db_session, org_id=org.id, name="Test endpoint", url=_SAFE_URL, events=[FINDING_OPENED]
    )
    finding = _make_finding(db_session, org)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="upstream exploded")

    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        finding_id=finding.id,
        event_type=FINDING_OPENED,
        payload={"type": FINDING_OPENED},
        status=WebhookDeliveryStatus.PENDING,
        attempt_count=0,
    )
    db_session.add(delivery)
    db_session.flush()

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(WebhookDeliveryError):
        deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    db_session.refresh(delivery)
    assert delivery.status is WebhookDeliveryStatus.FAILED
    assert delivery.http_status == 500
    assert delivery.attempt_count == 1
    assert delivery.error_message == "HTTP 500: upstream exploded"


def test_an_html_error_page_is_recorded_as_a_short_text_summary(db_session: Session):
    from kestrel.db.models.in_app_notification import OperatorInAppNotification
    from kestrel.testing import make_operator

    org = make_organization(db_session)
    admin = make_operator(db_session, org)
    endpoint, _secret = create_endpoint(db_session, org_id=org.id, name="Proxy", url=_SAFE_URL, events=[FINDING_OPENED])
    finding = _make_finding(db_session, org)
    page = (
        "<html><head><title>502 Bad Gateway</title><style>h1{color:red}</style></head>"
        "<body><h1>502 Bad Gateway</h1>" + "<p>padding text</p>" * 100 + "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text=page, headers={"Content-Type": "text/html"})

    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        finding_id=finding.id,
        event_type=FINDING_OPENED,
        payload={"type": FINDING_OPENED},
        status=WebhookDeliveryStatus.PENDING,
        attempt_count=0,
    )
    db_session.add(delivery)
    db_session.flush()

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(WebhookDeliveryError):
        deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    db_session.refresh(delivery)
    message = delivery.error_message or ""
    assert message.startswith("HTTP 502: 502 Bad Gateway 502 Bad Gateway padding text")
    assert "<" not in message
    assert "color:red" not in message
    assert len(message) <= 220

    notice = db_session.scalars(
        select(OperatorInAppNotification).where(OperatorInAppNotification.operator_id == admin.id)
    ).one()
    assert "<" not in notice.body
    assert notice.body == f"{FINDING_OPENED} · {message}"


@pytest.mark.parametrize(
    "unsafe_url",
    ["https://127.0.0.1/hook", "http://8.8.8.8/hook"],
    ids=["loopback", "plain-http-legacy-row"],
)
def test_deliver_webhook_delivery_rejects_unsafe_endpoint_url(db_session: Session, unsafe_url: str):
    org = make_organization(db_session)
    # create_endpoint validates at creation time too, so build the row directly
    # to exercise delivery's own defense-in-depth re-check.
    from kestrel.secrets.crypto import EnvKeyProvider, encrypt_secret
    from kestrel.webhooks.authoring import endpoint_secret_context, generate_signing_secret

    provider = EnvKeyProvider()
    secret = generate_signing_secret()
    endpoint_id = uuid.uuid4()
    encrypted = encrypt_secret(provider, org.id, secret, context=endpoint_secret_context(endpoint_id))

    from kestrel.db.models.webhook import WebhookEndpoint

    endpoint = WebhookEndpoint(
        id=endpoint_id,
        org_id=org.id,
        name="Unsafe",
        url=unsafe_url,
        events=[FINDING_OPENED],
        secret_ciphertext=encrypted.ciphertext,
        secret_nonce=encrypted.nonce,
        secret_key_version=encrypted.key_version,
        is_enabled=True,
    )
    db_session.add(endpoint)
    db_session.flush()
    finding = _make_finding(db_session, org)

    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        finding_id=finding.id,
        event_type=FINDING_OPENED,
        payload={"type": FINDING_OPENED},
        status=WebhookDeliveryStatus.PENDING,
        attempt_count=0,
    )
    db_session.add(delivery)
    db_session.flush()

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must never run
        raise AssertionError("delivery must not reach the transport for an unsafe URL")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(WebhookDeliveryError):
        deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    db_session.refresh(delivery)
    assert delivery.status is WebhookDeliveryStatus.FAILED


def test_decrypt_endpoint_secret_roundtrips_through_envelope_encryption(db_session: Session):
    org = make_organization(db_session)
    endpoint, plaintext_secret = create_endpoint(
        db_session, org_id=org.id, name="Test endpoint", url=_SAFE_URL, events=[FINDING_OPENED]
    )
    assert decrypt_endpoint_secret(endpoint) == plaintext_secret


def test_schedule_finding_webhooks_only_creates_deliveries_for_subscribed_enabled_endpoints(db_session: Session):
    org = make_organization(db_session)
    subscribed, _ = create_endpoint(db_session, org_id=org.id, name="Subscribed", url=_SAFE_URL, events=[FINDING_OPENED])
    _not_subscribed, _secret = create_endpoint(
        db_session, org_id=org.id, name="Not subscribed", url="https://8.8.4.4/hook", events=[FINDING_RESOLVED]
    )
    disabled, _ = create_endpoint(
        db_session, org_id=org.id, name="Disabled", url="https://1.1.1.1/hook", events=[FINDING_OPENED]
    )
    disabled.is_enabled = False
    db_session.flush()

    finding = _make_finding(db_session, org)

    created = schedule_finding_webhooks(db_session, org_id=org.id, event_type=FINDING_OPENED, finding=finding)

    deliveries = db_session.scalars(select(WebhookDelivery).where(WebhookDelivery.org_id == org.id)).all()
    endpoint_ids = {d.webhook_endpoint_id for d in deliveries}
    assert endpoint_ids == {subscribed.id}
    assert len(created) == 1


def _pending_delivery(db_session: Session, org, endpoint, finding) -> WebhookDelivery:
    delivery = WebhookDelivery(
        id=uuid.uuid4(),
        org_id=org.id,
        webhook_endpoint_id=endpoint.id,
        finding_id=finding.id,
        event_type=FINDING_OPENED,
        payload={"type": FINDING_OPENED},
        status=WebhookDeliveryStatus.PENDING,
        attempt_count=0,
    )
    db_session.add(delivery)
    db_session.flush()
    return delivery


@pytest.mark.parametrize(
    ("status_code", "permanent"),
    [(400, True), (401, True), (404, True), (410, True), (408, False), (429, False), (500, False), (503, False)],
)
def test_receiver_status_decides_whether_the_worker_retries(db_session: Session, status_code: int, permanent: bool):
    """A 4xx will answer the same way next time; throttles, timeouts and 5xx
    deserve another attempt."""
    org = make_organization(db_session)
    endpoint, _secret = create_endpoint(db_session, org_id=org.id, name="E", url=_SAFE_URL, events=[FINDING_OPENED])
    delivery = _pending_delivery(db_session, org, endpoint, _make_finding(db_session, org))
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status_code, text="no")))

    with pytest.raises(WebhookDeliveryError) as excinfo:
        deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    assert excinfo.value.permanent is permanent


def test_a_disabled_endpoint_and_an_unsafe_url_are_permanent_failures(db_session: Session):
    org = make_organization(db_session)
    endpoint, _secret = create_endpoint(db_session, org_id=org.id, name="E", url=_SAFE_URL, events=[FINDING_OPENED])
    finding = _make_finding(db_session, org)
    endpoint.is_enabled = False
    db_session.flush()
    posted: list[httpx.Request] = []
    client = httpx.Client(transport=httpx.MockTransport(lambda request: posted.append(request) or httpx.Response(200)))

    with pytest.raises(WebhookDeliveryError) as excinfo:
        deliver_webhook_delivery(db_session, _pending_delivery(db_session, org, endpoint, finding).id, http_client=client)
    assert excinfo.value.permanent is True

    endpoint.is_enabled = True
    endpoint.url = "http://8.8.8.8/plain"  # plaintext http: rejected at delivery time too
    db_session.flush()
    with pytest.raises(WebhookDeliveryError) as excinfo:
        deliver_webhook_delivery(db_session, _pending_delivery(db_session, org, endpoint, finding).id, http_client=client)
    assert excinfo.value.permanent is True
    assert posted == []


def test_a_delivery_that_already_succeeded_is_not_posted_again(db_session: Session):
    """A redelivered task or a manual retry racing the worker must not send
    the receiver the same event twice."""
    org = make_organization(db_session)
    endpoint, _secret = create_endpoint(db_session, org_id=org.id, name="E", url=_SAFE_URL, events=[FINDING_OPENED])
    delivery = _pending_delivery(db_session, org, endpoint, _make_finding(db_session, org))
    posted: list[httpx.Request] = []
    client = httpx.Client(transport=httpx.MockTransport(lambda request: posted.append(request) or httpx.Response(200)))

    first = deliver_webhook_delivery(db_session, delivery.id, http_client=client)
    second = deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    assert first.status is WebhookDeliveryStatus.SUCCESS
    assert second is first
    assert len(posted) == 1
    assert delivery.attempt_count == 1


def test_only_a_capped_prefix_of_an_error_body_is_read(db_session: Session):
    """A receiver streaming an endless error body must not be read to the end."""
    from kestrel.webhooks.delivery import MAX_RESPONSE_BODY_BYTES

    org = make_organization(db_session)
    endpoint, _secret = create_endpoint(db_session, org_id=org.id, name="E", url=_SAFE_URL, events=[FINDING_OPENED])
    delivery = _pending_delivery(db_session, org, endpoint, _make_finding(db_session, org))
    sent = 0

    def endless():
        nonlocal sent
        for _ in range(1024):  # 16 MiB if read to the end
            sent += 16 * 1024
            yield b"x" * (16 * 1024)

    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500, content=endless())))
    with pytest.raises(WebhookDeliveryError):
        deliver_webhook_delivery(db_session, delivery.id, http_client=client)

    assert sent <= MAX_RESPONSE_BODY_BYTES + 16 * 1024
    assert delivery.error_message is not None
    assert delivery.error_message.startswith("HTTP 500: xxx")


@pytest.fixture
def committed_delivery(db_engine):
    """A delivery committed for real, so a second connection can lock it."""
    from kestrel.db.models.org import Organization
    from kestrel.db.models.webhook import WebhookEndpoint
    from sqlalchemy import delete

    with Session(db_engine) as setup:
        org = make_organization(setup)
        endpoint, _secret = create_endpoint(setup, org_id=org.id, name="E", url=_SAFE_URL, events=[FINDING_OPENED])
        delivery = WebhookDelivery(
            id=uuid.uuid4(),
            org_id=org.id,
            webhook_endpoint_id=endpoint.id,
            event_type=FINDING_OPENED,
            payload={"type": FINDING_OPENED},
            status=WebhookDeliveryStatus.PENDING,
            attempt_count=0,
        )
        setup.add(delivery)
        setup.commit()
        org_id, delivery_id = org.id, delivery.id
    try:
        yield delivery_id
    finally:
        with Session(db_engine) as cleanup:
            cleanup.execute(delete(WebhookDelivery).where(WebhookDelivery.org_id == org_id))
            cleanup.execute(delete(WebhookEndpoint).where(WebhookEndpoint.org_id == org_id))
            cleanup.execute(delete(Organization).where(Organization.id == org_id))
            cleanup.commit()


def test_a_delivery_locked_by_another_worker_is_not_posted_twice(db_engine, committed_delivery):
    """Two tasks for one delivery overlapping: the second must not POST while
    the first holds the row, and finds SUCCESS once the first commits."""
    posted: list[httpx.Request] = []
    client = httpx.Client(transport=httpx.MockTransport(lambda request: posted.append(request) or httpx.Response(200)))

    with Session(db_engine) as first, Session(db_engine) as second:
        delivered = deliver_webhook_delivery(first, committed_delivery, http_client=client)
        assert delivered.status is WebhookDeliveryStatus.SUCCESS
        # `first` still holds the row lock: it has not committed yet.
        skipped = deliver_webhook_delivery(second, committed_delivery, http_client=client)
        assert skipped.status is WebhookDeliveryStatus.PENDING
        assert len(posted) == 1
        second.rollback()

        first.commit()
        again = deliver_webhook_delivery(second, committed_delivery, http_client=client)
        assert again.status is WebhookDeliveryStatus.SUCCESS
        assert len(posted) == 1
        second.rollback()


def test_worker_backoff_doubles_from_thirty_seconds():
    from kestrel_worker.tasks.webhooks import default_retry_delay_for

    assert [default_retry_delay_for(n) for n in range(5)] == [30, 60, 120, 240, 480]
