# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""An authenticated FastAPI ``TestClient`` for the Kestrel API.

Imports of ``fastapi`` / ``kestrel_api`` happen inside the function, not at
module scope: ``kestrel`` is the core library and does not depend on the API
app, so ``import kestrel.testing`` must keep working in a process where only
the core package is installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.org import Organization
from kestrel.testing.factories import make_operator, make_organization

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


def api_client(
    session: Session,
    role: OperatorRole | str = OperatorRole.ADMIN,
    *,
    org: Organization | None = None,
    task_queue: Any | None = None,
) -> TestClient:
    """A TestClient authenticated as a new Operator with ``role``.

    The client is built on a *fresh* application (``create_app()``), not the
    process-global ``kestrel_api.main.app``, so the dependency overrides
    installed here cannot leak into another test that forgot to clear them.

    ``session`` is bound as the request-scoped DB session, so route handlers
    see the caller's (typically rolled-back) transaction. Pass ``task_queue``
    to capture work the routes would have enqueued instead of reaching Celery.

    The returned client carries three extra attributes for convenience:
    ``kestrel_org``, ``kestrel_operator`` and ``kestrel_token``.
    """
    from fastapi.testclient import TestClient
    from kestrel_api.deps import get_db
    from kestrel_api.main import create_app
    from kestrel_api.tasks_client import get_task_queue

    from kestrel.auth.service import create_session

    if isinstance(role, str):
        role = OperatorRole(role)
    if org is None:
        org = make_organization(session)

    operator = make_operator(session, org, role=role)
    _session_row, raw_token = create_session(session, operator)
    session.flush()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    if task_queue is not None:
        app.dependency_overrides[get_task_queue] = lambda: task_queue

    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {raw_token}"})
    client.kestrel_org = org  # type: ignore[attr-defined]
    client.kestrel_operator = operator  # type: ignore[attr-defined]
    client.kestrel_token = raw_token  # type: ignore[attr-defined]
    return client
