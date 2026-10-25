# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Lightweight Celery client for enqueuing worker tasks from the API,
without depending on the kestrel_worker package -- the API only needs the
task name and the shared broker URL, not the task's implementation, so
apps/api and apps/worker stay independently deployable.

Two seams matter here:

* The ``Celery`` app is built lazily (``get_celery_client``) rather than at
  import, so importing a router does not read ``REDIS_URL`` or construct a
  broker connection object.
* Route handlers depend on ``get_task_queue`` instead of calling the module
  functions directly. That gives callers *one* override point --
  ``app.dependency_overrides[get_task_queue]`` -- rather than needing to
  monkeypatch the by-name import in every router module that enqueues.

The module-level ``enqueue_connector_sync`` / ``enqueue_webhook_deliveries``
functions still exist and behave exactly as before.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from celery import Celery
    from kestrel.notifications.email import NotificationEmail

_LOG = logging.getLogger(__name__)

_celery_client: Celery | None = None


def get_broker_url() -> str:
    """Broker/backend URL, read fresh from the environment."""
    return os.environ.get("REDIS_URL", "redis://localhost:6380/0")


def get_celery_client() -> Celery:
    """The process-wide Celery client, created on first use and memoized."""
    global _celery_client
    if _celery_client is None:
        from celery import Celery

        broker_url = get_broker_url()
        _celery_client = Celery("kestrel_api_client", broker=broker_url, backend=broker_url)
    return _celery_client


class TaskQueue(Protocol):
    """What route handlers need from the worker queue."""

    def enqueue_connector_sync(self, *, connector_instance_id: str, connector_name: str, config: dict) -> str: ...

    def enqueue_webhook_deliveries(self, delivery_ids: list[str]) -> list[str]: ...


class CeleryTaskQueue:
    """The production TaskQueue: sends tasks over the shared Celery broker."""

    def enqueue_connector_sync(self, *, connector_instance_id: str, connector_name: str, config: dict) -> str:
        result = get_celery_client().send_task(
            "kestrel.sync.run_connector_sync",
            kwargs={
                "connector_instance_id": connector_instance_id,
                "connector_name": connector_name,
                "config": config,
                "triggered_by": "api",
            },
        )
        return str(result.id)

    def enqueue_webhook_deliveries(self, delivery_ids: list[str]) -> list[str]:
        """Enqueues one Celery task per delivery id. Best-effort: callers have
        already committed the pending delivery rows; a broker outage leaves them
        pending for a later retry/manual re-drive.
        """
        task_ids: list[str] = []
        for delivery_id in delivery_ids:
            result = get_celery_client().send_task(
                "kestrel.webhooks.deliver",
                kwargs={"delivery_id": delivery_id},
            )
            task_ids.append(str(result.id))
        return task_ids


def get_task_queue() -> TaskQueue:
    """FastAPI dependency. Override this in tests to capture enqueued work."""
    return CeleryTaskQueue()


def enqueue_connector_sync(*, connector_instance_id: str, connector_name: str, config: dict) -> str:
    return CeleryTaskQueue().enqueue_connector_sync(
        connector_instance_id=connector_instance_id,
        connector_name=connector_name,
        config=config,
    )


def enqueue_webhook_deliveries(delivery_ids: list[str]) -> list[str]:
    return CeleryTaskQueue().enqueue_webhook_deliveries(delivery_ids)


def enqueue_notification_emails(items: list[NotificationEmail]) -> None:
    """Email dispatcher for API sessions (see kestrel.notifications.email).

    Runs after the triggering change has committed, so it must not raise: a
    broker outage drops the email (the in-app notification is already saved)
    and is logged.
    """
    try:
        get_celery_client().send_task(
            "kestrel.notifications.send_emails",
            kwargs={"items": [asdict(item) for item in items]},
        )
    except Exception:  # noqa: BLE001 -- any broker failure; see docstring
        _LOG.exception("notification_email_enqueue_failed")


def __getattr__(name: str) -> Any:
    """``REDIS_URL`` used to be a module constant bound at import; keep the
    name working, resolved fresh from the environment."""
    if name == "REDIS_URL":
        return get_broker_url()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
