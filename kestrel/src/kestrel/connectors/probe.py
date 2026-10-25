# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Probe a connector instance's live credentials via health_check."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from kestrel.connectors.sdk.base import Transport
from kestrel.connectors.sdk.registry import load_connector, load_fixture_transport_builder
from kestrel.db.models.connector import Connector, ConnectorInstance, SyncMode
from kestrel.secrets.store import get_secrets

logger = logging.getLogger(__name__)


class ConnectorProbeError(ValueError):
    """Credentials / mode / connector issues preventing a probe."""


def probe_connector_instance(session: Session, instance: ConnectorInstance) -> dict[str, Any]:
    """Run collector.health_check() with the instance's configured transport.

    Fixture mode uses FixtureTransport (no secrets). Live mode decrypts secrets
    and calls authenticate(). Never returns secret values.
    """
    connector_row = session.get(Connector, instance.connector_id)
    if connector_row is None:
        raise ConnectorProbeError("Connector instance references an unknown connector")

    try:
        connector = load_connector(connector_row.name)
    except (ValueError, ImportError) as exc:
        raise ConnectorProbeError(f"Could not load connector '{connector_row.name}': {exc}") from exc

    from kestrel.secrets.scrub import scrub_text

    config = dict(instance.config or {})
    config["auth_method"] = instance.auth_method.value
    secret_values: list[str] = []

    transport: Transport
    try:
        if instance.sync_mode == SyncMode.FIXTURES:
            transport = load_fixture_transport_builder(connector_row.name)()
            connector.configure(config)
        else:
            secrets = get_secrets(
                session,
                org_id=instance.org_id,
                connector_instance_id=instance.id,
            )
            if not secrets:
                raise ConnectorProbeError("Live mode requires configured secrets before testing connection")
            secret_values = list(secrets.values())
            transport = connector.authenticate(config, secrets)

        collector = connector.build_collector(transport)
        result = collector.health_check()
    except ConnectorProbeError:
        raise
    except Exception as exc:
        logger.warning(
            "connector probe failed instance_id=%s connector=%s mode=%s",
            instance.id,
            connector_row.name,
            instance.sync_mode.value,
            exc_info=True,
        )
        return {
            "ok": False,
            "healthy": False,
            "sync_mode": instance.sync_mode.value,
            "auth_method": instance.auth_method.value,
            "message": scrub_text(str(exc), secret_values),
            "checked_permissions": {},
        }

    return {
        "ok": bool(result.healthy),
        "healthy": bool(result.healthy),
        "sync_mode": instance.sync_mode.value,
        "auth_method": instance.auth_method.value,
        "message": scrub_text(result.message, secret_values),
        "checked_permissions": dict(result.checked_permissions or {}),
    }


def probe_connector_config(
    *,
    connector_name: str,
    config: dict[str, Any],
    auth_method: str,
    sync_mode: str,
    secrets: dict[str, str] | None,
) -> dict[str, Any]:
    """Run ``health_check`` for credentials that have not been saved.

    The wizard calls this before creating the instance so a wrong token or a
    missing scope is caught while the operator is still looking at the form.
    Nothing is persisted, nothing is logged beyond the failure class, and the
    response never contains the secrets it was given.
    """
    from kestrel.secrets.scrub import scrub_text
    from kestrel.security.ssrf import UnsafeConnectorURLError, validate_connector_config_urls

    try:
        connector = load_connector(connector_name)
    except (ValueError, ImportError) as exc:
        raise ConnectorProbeError(f"Could not load connector '{connector_name}': {exc}") from exc

    effective = dict(config or {})
    effective["auth_method"] = auth_method
    secret_values = list((secrets or {}).values())

    try:
        validate_connector_config_urls(effective, require_https=sync_mode != SyncMode.FIXTURES.value)
    except UnsafeConnectorURLError as exc:
        raise ConnectorProbeError(str(exc)) from exc

    transport: Transport
    try:
        if sync_mode == SyncMode.FIXTURES.value:
            transport = load_fixture_transport_builder(connector_name)()
            connector.configure(effective)
        else:
            if not secrets:
                raise ConnectorProbeError("Live mode needs the secret fields filled in before the connection can be tested")
            transport = connector.authenticate(effective, secrets)
        collector = connector.build_collector(transport)
        result = collector.health_check()
    except ConnectorProbeError:
        raise
    except Exception as exc:
        logger.warning("connector config probe failed connector=%s mode=%s", connector_name, sync_mode, exc_info=True)
        return {
            "ok": False,
            "healthy": False,
            "sync_mode": sync_mode,
            "auth_method": auth_method,
            "message": scrub_text(f"{type(exc).__name__}: {exc}", secret_values),
            "checked_permissions": {},
        }

    return {
        "ok": bool(result.healthy),
        "healthy": bool(result.healthy),
        "sync_mode": sync_mode,
        "auth_method": auth_method,
        "message": scrub_text(result.message, secret_values),
        "checked_permissions": dict(result.checked_permissions or {}),
    }
