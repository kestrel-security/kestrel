# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel sync` -- runs a connector sync, either enqueued on the worker
(default) or in-process (`--no-async`) for contributors running without
the full Docker stack.
"""

from __future__ import annotations

import uuid

import typer

from kestrel.connectors.sdk.registry import load_connector, load_fixture_transport_builder
from kestrel.db.models.connector import ConnectorInstance, SyncMode
from kestrel.db.session import get_sessionmaker
from kestrel.demo import DEMO_SYNC_REFUSAL, is_demo_instance
from kestrel.sync.execute import start_run, sync_and_evaluate
from kestrel.sync.lock import active_run_for


def sync(
    connector_instance_id: uuid.UUID = typer.Option(..., "--instance", help="ConnectorInstance id to sync."),
    connector_name: str = typer.Option(..., "--connector", help="Installed connector name, e.g. 'github'."),
    no_async: bool = typer.Option(False, "--no-async", help="Run in-process instead of enqueuing on the worker."),
) -> None:
    """Run one connector instance's sync, on the worker (default) or in-process."""
    if no_async:
        try:
            connector = load_connector(connector_name)
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        session = get_sessionmaker()()
        try:
            instance = session.get(ConnectorInstance, connector_instance_id)
            if instance is None:
                typer.secho("Connector instance not found", fg=typer.colors.RED)
                raise typer.Exit(code=1)
            if active_run_for(session, connector_instance_id=instance.id) is not None:
                typer.secho("A sync of this connector instance is already running", fg=typer.colors.RED)
                raise typer.Exit(code=1)
            if is_demo_instance(instance.config, instance.sync_mode.value):
                typer.secho(DEMO_SYNC_REFUSAL, fg=typer.colors.RED)
                raise typer.Exit(code=1)

            transport_override = None
            if instance.sync_mode == SyncMode.FIXTURES:
                transport_override = load_fixture_transport_builder(connector_name)()

            effective_config = {**(instance.config or {}), "auth_method": instance.auth_method.value}
            # Same lifecycle as the worker task: the RUNNING row is committed
            # first, a failure is recorded rather than rolled away, and a
            # partial run is evaluated too.
            started = start_run(session, connector_instance_id=instance.id)
            outcome = sync_and_evaluate(
                session,
                run_id=started.id,
                connector_instance_id=instance.id,
                connector=connector,
                config=effective_config,
                transport_override=transport_override,
            )
            run = outcome.run
            if outcome.webhook_delivery_ids:
                from kestrel.webhooks.delivery import WebhookDeliveryError, deliver_webhook_delivery

                for delivery_id in outcome.webhook_delivery_ids:
                    try:
                        deliver_webhook_delivery(session, delivery_id)
                        session.commit()
                    except WebhookDeliveryError:
                        session.commit()
            typer.secho(f"Sync {run.status.value}: {run.object_counts}", fg=typer.colors.GREEN)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return

    session = get_sessionmaker()()
    try:
        instance = session.get(ConnectorInstance, connector_instance_id)
        if instance is None:
            typer.secho("Connector instance not found", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        config = dict(instance.config)
    finally:
        session.close()

    from kestrel_worker.tasks.sync import run_connector_sync

    task = run_connector_sync.delay(
        connector_instance_id=connector_instance_id, connector_name=connector_name, config=config
    )
    typer.echo(f"Enqueued sync task {task.id}")
