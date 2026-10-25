# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector instance authoring: ensure the global Connector catalog row
exists from entry-point discovery, create the Application /
ApplicationInstance inventory rows, and bind a ConnectorInstance.

This is the UI/API create path. Secrets stay out of band
(`ConnectorSecret`); fixture-mode instances need none.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.connectors.sdk.base import Connector as ConnectorProtocol
from kestrel.connectors.sdk.registry import discover_connectors
from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.db.models.connector import (
    AuthMethod,
    Connector,
    ConnectorInstance,
    ConnectorSource,
    SyncMode,
)
from kestrel.scheduling.cron import InvalidCronError, validate_cron
from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_config_urls


class ConnectorAuthoringError(ValueError):
    """Raised when a create cannot proceed. Callers map this to HTTP 400."""


_APPLICATION_TYPE_BY_CONNECTOR: dict[str, ApplicationType] = {
    "github": ApplicationType.GITHUB,
    "google_workspace": ApplicationType.GOOGLE_WORKSPACE,
    "slack": ApplicationType.SLACK,
    "okta": ApplicationType.OKTA,
}


def _connector_source(connector_name: str) -> ConnectorSource:
    if connector_name in _APPLICATION_TYPE_BY_CONNECTOR:
        return ConnectorSource.BUILTIN
    return ConnectorSource.CUSTOM


def resolve_auth_method(connector_name: str, auth_method: str) -> AuthMethod:
    """Accept the connector manifest's auth method id (e.g. api_key)."""
    discovered = discover_connectors()
    if connector_name not in discovered:
        available = ", ".join(sorted(discovered)) or "(none installed)"
        raise ConnectorAuthoringError(f"Connector '{connector_name}' is not installed. Available: {available}")
    connector_cls: type[ConnectorProtocol] = discovered[connector_name].connector_class
    manifest = connector_cls.manifest
    if manifest.auth_method(auth_method) is None:
        allowed = ", ".join(m.id for m in manifest.auth_methods) or "(none)"
        raise ConnectorAuthoringError(
            f"Invalid auth_method '{auth_method}' for connector '{connector_name}'. Allowed: {allowed}"
        )
    try:
        return AuthMethod(auth_method)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in AuthMethod)
        raise ConnectorAuthoringError(f"Invalid auth_method '{auth_method}'. Allowed: {allowed}") from exc


def ensure_connector_row(session: Session, connector_name: str) -> Connector:
    """Upsert the global `connectors` catalog row from the installed package
    manifest. Connectors are code-level (unique on name), not per-org."""
    discovered = discover_connectors()
    if connector_name not in discovered:
        available = ", ".join(sorted(discovered)) or "(none installed)"
        raise ConnectorAuthoringError(f"Connector '{connector_name}' is not installed. Available: {available}")

    reg = discovered[connector_name]
    connector_cls: type[ConnectorProtocol] = reg.connector_class
    manifest = connector_cls.manifest
    existing = session.scalars(select(Connector).where(Connector.name == connector_name)).one_or_none()
    if existing is not None:
        # Keep version/manifest current when packages are upgraded; do not
        # invent a second row (name is unique).
        existing.version = manifest.version
        existing.manifest = manifest.model_dump()
        existing.supported_object_types = [ot.name for ot in manifest.object_types]
        return existing

    row = Connector(
        id=uuid.uuid4(),
        name=connector_name,
        version=manifest.version,
        manifest=manifest.model_dump(),
        supported_object_types=[ot.name for ot in manifest.object_types],
        source=_connector_source(connector_name),
    )
    session.add(row)
    session.flush()
    return row


def create_connector_instance(
    session: Session,
    *,
    org_id: uuid.UUID,
    connector_name: str,
    display_name: str,
    external_tenant_ref: str,
    config: dict,
    auth_method: str,
    sync_mode: str = SyncMode.FIXTURES.value,
    schedule_cron: str | None = None,
    application_instance_id: uuid.UUID | None = None,
) -> ConnectorInstance:
    """Create a ConnectorInstance, ensuring catalog + inventory rows exist.

    When `application_instance_id` is omitted, creates Application +
    ApplicationInstance for this org. When provided, attaches to that
    existing inventory row (must belong to the same org).
    """
    display_name = display_name.strip()
    external_tenant_ref = external_tenant_ref.strip()
    if not display_name:
        raise ConnectorAuthoringError("display_name is required")
    if not external_tenant_ref and application_instance_id is None:
        raise ConnectorAuthoringError("external_tenant_ref is required when creating a new application instance")

    try:
        # Live instances send their stored credentials to these URLs.
        validate_connector_config_urls(config, require_https=sync_mode != SyncMode.FIXTURES.value)
    except UnsafeConnectorURLError as exc:
        raise ConnectorAuthoringError(str(exc)) from exc

    from kestrel.connectors.secrets_authoring import reject_secrets_in_config

    reject_secrets_in_config(config)

    if schedule_cron is not None:
        try:
            validate_cron(schedule_cron)
        except InvalidCronError as exc:
            raise ConnectorAuthoringError(str(exc)) from exc

    auth = resolve_auth_method(connector_name, auth_method)

    try:
        mode = SyncMode(sync_mode)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in SyncMode)
        raise ConnectorAuthoringError(f"Invalid sync_mode '{sync_mode}'. Allowed: {allowed}") from exc

    connector_row = ensure_connector_row(session, connector_name)

    if application_instance_id is not None:
        app_instance = session.get(ApplicationInstance, application_instance_id)
        if app_instance is None or app_instance.org_id != org_id:
            raise ConnectorAuthoringError("application_instance not found in this organization")
    else:
        app_type = _APPLICATION_TYPE_BY_CONNECTOR.get(connector_name, ApplicationType.CUSTOM)
        discovered = discover_connectors()
        connector_cls: type[ConnectorProtocol] = discovered[connector_name].connector_class
        manifest = connector_cls.manifest
        application = Application(
            id=uuid.uuid4(),
            org_id=org_id,
            name=manifest.display_name,
            application_type=app_type,
        )
        session.add(application)
        session.flush()
        app_instance = ApplicationInstance(
            id=uuid.uuid4(),
            org_id=org_id,
            application_id=application.id,
            display_name=display_name,
            external_tenant_ref=external_tenant_ref,
        )
        session.add(app_instance)
        session.flush()

    instance = ConnectorInstance(
        id=uuid.uuid4(),
        org_id=org_id,
        connector_id=connector_row.id,
        application_instance_id=app_instance.id,
        config=config,
        auth_method=auth,
        sync_mode=mode,
        schedule_cron=schedule_cron,
    )
    session.add(instance)
    session.flush()
    return instance
