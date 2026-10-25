# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Row factories for the tenanted core entities.

Each factory flushes so the caller gets a populated primary key back, and none
of them commit -- callers are expected to be running inside a transaction that
gets rolled back. Defaults are chosen so a factory can always be called with
just its required parents; every field stays overridable.

Names are made unique per call (``uuid4().hex[:8]`` suffixes) so tests that do
commit against a shared database do not collide on the unique constraints
(``organizations.slug``, ``operators (org_id, email)``, ``connectors.name``).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.auth.passwords import hash_password
from kestrel.db.models.application import (
    Application,
    ApplicationInstance,
    ApplicationInstanceStatus,
    ApplicationType,
)
from kestrel.db.models.connector import (
    AuthMethod,
    Connector,
    ConnectorInstance,
    ConnectorSource,
    SyncMode,
)
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization

DEFAULT_PASSWORD = "correct-horse-battery-staple"


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


def make_organization(session: Session, *, name: str = "Test Org", slug: str | None = None) -> Organization:
    org = Organization(id=uuid.uuid4(), name=name, slug=slug or f"test-org-{_suffix()}")
    session.add(org)
    session.flush()
    return org


def make_operator(
    session: Session,
    org: Organization,
    *,
    role: OperatorRole = OperatorRole.ADMIN,
    email: str | None = None,
    display_name: str = "Test Operator",
    password: str | None = DEFAULT_PASSWORD,
    is_active: bool = True,
) -> Operator:
    operator = Operator(
        id=uuid.uuid4(),
        org_id=org.id,
        email=email or f"test-{_suffix()}@example.com",
        display_name=display_name,
        password_hash=hash_password(password) if password is not None else None,
        role=role,
        is_active=is_active,
    )
    session.add(operator)
    session.flush()
    return operator


def make_application(
    session: Session,
    org: Organization,
    *,
    name: str = "GitHub",
    application_type: ApplicationType = ApplicationType.GITHUB,
    vendor: str | None = None,
    description: str | None = None,
) -> Application:
    application = Application(
        id=uuid.uuid4(),
        org_id=org.id,
        name=name,
        application_type=application_type,
        vendor=vendor,
        description=description,
    )
    session.add(application)
    session.flush()
    return application


def make_application_instance(
    session: Session,
    org: Organization,
    application: Application | None = None,
    *,
    display_name: str = "Test Application Instance",
    external_tenant_ref: str | None = None,
    status: ApplicationInstanceStatus = ApplicationInstanceStatus.ACTIVE,
) -> ApplicationInstance:
    if application is None:
        application = make_application(session, org)
    instance = ApplicationInstance(
        id=uuid.uuid4(),
        org_id=org.id,
        application_id=application.id,
        display_name=display_name,
        external_tenant_ref=external_tenant_ref or f"tenant-{_suffix()}",
        status=status,
    )
    session.add(instance)
    session.flush()
    return instance


def make_connector(
    session: Session,
    *,
    name: str | None = None,
    version: str = "0.1.0",
    manifest: dict | None = None,
    supported_object_types: list | None = None,
    source: ConnectorSource = ConnectorSource.BUILTIN,
) -> Connector:
    """Connector rows are global (registry of installed code), not org-scoped,
    and ``connectors.name`` is unique -- so a named connector is reused when it
    already exists rather than colliding."""
    if name is not None:
        existing = session.scalars(select(Connector).where(Connector.name == name)).one_or_none()
        if existing is not None:
            return existing
    connector = Connector(
        id=uuid.uuid4(),
        name=name or f"test-connector-{_suffix()}",
        version=version,
        manifest=manifest if manifest is not None else {},
        supported_object_types=supported_object_types if supported_object_types is not None else [],
        source=source,
    )
    session.add(connector)
    session.flush()
    return connector


def make_connector_instance(
    session: Session,
    org: Organization,
    *,
    connector: Connector | None = None,
    application_instance: ApplicationInstance | None = None,
    config: dict | None = None,
    auth_method: AuthMethod = AuthMethod.PAT,
    sync_mode: SyncMode = SyncMode.FIXTURES,
    schedule_cron: str | None = None,
) -> ConnectorInstance:
    if connector is None:
        connector = make_connector(session)
    if application_instance is None:
        application_instance = make_application_instance(session, org)
    instance = ConnectorInstance(
        id=uuid.uuid4(),
        org_id=org.id,
        connector_id=connector.id,
        application_instance_id=application_instance.id,
        config=config if config is not None else {},
        auth_method=auth_method,
        sync_mode=sync_mode,
        schedule_cron=schedule_cron,
    )
    session.add(instance)
    session.flush()
    return instance
