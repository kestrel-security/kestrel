# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector management API: installed connector registry, configured
instances with health/sync state, create + schedule + secrets,
manual sync trigger, run history -- backs the Connector Management UI.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from kestrel.audit.service import record_audit_event
from kestrel.connectors.authoring import ConnectorAuthoringError, create_connector_instance
from kestrel.connectors.delete import ConnectorDeleteError, delete_connector_instance
from kestrel.connectors.health import (
    DEFAULT_STALE_AFTER_HOURS,
    ConnectorHealthError,
    classify_sync_health,
    connector_health_center,
)
from kestrel.connectors.probe import ConnectorProbeError, probe_connector_config, probe_connector_instance
from kestrel.connectors.run_detail import connector_run_detail
from kestrel.connectors.run_drift import list_run_changes
from kestrel.connectors.sdk.base import Connector as ConnectorProtocol
from kestrel.connectors.sdk.registry import discover_connectors
from kestrel.connectors.secrets_authoring import (
    declared_config_fields,
    reject_secrets_in_config,
    secret_status,
    upsert_secrets,
)
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import (
    AuthMethod,
    Connector,
    ConnectorInstance,
    ConnectorRun,
    ConnectorRunStatus,
    SyncMode,
)
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.demo import is_demo_instance
from kestrel.scheduling.cron import InvalidCronError, validate_cron
from kestrel.secrets.store import delete_secrets
from kestrel.security.ssrf import UnsafeConnectorURLError, changed_endpoint_fields, validate_connector_config_urls
from kestrel.sync.lock import expire_stale_running_runs
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel_api.deps import get_current_org, get_db, require_role
from kestrel_api.sync_trigger import enqueue_instance_sync
from kestrel_api.tasks_client import TaskQueue, get_task_queue

router = APIRouter(tags=["connectors"])


@router.get("/connectors")
def list_connectors(
    _org: Organization = Depends(get_current_org),
) -> list[dict]:
    """Installed connector packages (entry-point discovery), with manifest
    hints the create UI needs (auth methods, setup guides, example config)."""
    discovered = discover_connectors()
    out: list[dict] = []
    for name, reg in sorted(discovered.items()):
        connector_cls: type[ConnectorProtocol] = reg.connector_class
        manifest = connector_cls.manifest
        out.append(
            {
                "name": name,
                "display_name": manifest.display_name,
                "version": manifest.version,
                "description": manifest.description,
                "required_scopes": list(manifest.required_scopes),
                "setup_docs": manifest.setup_docs,
                "auth_methods": [
                    {
                        "id": m.id,
                        "label": m.label,
                        "config_fields": m.config_fields,
                        "optional_config_fields": m.optional_config_fields,
                        "secret_fields": m.secret_fields,
                        "setup_overview": m.setup_overview,
                        "setup_steps": [
                            {
                                "title": step.title,
                                "body": step.body,
                                "link_url": step.link_url,
                                "link_label": step.link_label,
                            }
                            for step in m.setup_steps
                        ],
                        "field_help": dict(m.field_help),
                        "scopes_note": m.scopes_note,
                    }
                    for m in manifest.auth_methods
                ],
                "example_config": manifest.example_config,
                "source": getattr(reg, "source", "builtin"),
            }
        )
    return out


def _instance_summary(
    db: Session,
    instance: ConnectorInstance,
    *,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
    now: datetime | None = None,
) -> dict:
    clock = now or datetime.now(UTC)
    runs = list(
        db.scalars(
            select(ConnectorRun)
            .where(ConnectorRun.connector_instance_id == instance.id)
            .order_by(ConnectorRun.started_at.desc())
        ).all()
    )
    last_run = runs[0] if runs else None
    last_success_at = None
    for run in runs:
        if run.status == ConnectorRunStatus.SUCCESS:
            last_success_at = run.finished_at or run.started_at
            break

    connector_row = db.get(Connector, instance.connector_id)
    app_instance = db.get(ApplicationInstance, instance.application_instance_id)
    last_status = last_run.status.value if last_run else None
    health = classify_sync_health(
        last_run_status=last_status,
        last_success_at=last_success_at,
        now=clock,
        stale_after_hours=stale_after_hours,
    )
    last_finished = last_run.finished_at if last_run else None
    last_started = last_run.started_at if last_run else None
    last_run_at = last_finished or last_started
    secrets = (
        secret_status(db, connector=connector_row, instance=instance)
        if connector_row is not None
        else {
            "declared_fields": [],
            "configured_fields": [],
            "missing_fields": [],
            "fields": [],
        }
    )
    return {
        "id": instance.id,
        "application_instance_id": instance.application_instance_id,
        "application_display_name": app_instance.display_name if app_instance else None,
        # Which tenant this instance actually reads (org login, workspace id,
        # domain). More useful on a list row than the auth method.
        "external_tenant_ref": app_instance.external_tenant_ref if app_instance else None,
        "connector_id": instance.connector_id,
        "connector_name": connector_row.name if connector_row else None,
        "connector_display_name": ((connector_row.manifest or {}).get("display_name") if connector_row else None)
        or (connector_row.name if connector_row else None),
        "auth_method": instance.auth_method.value,
        "sync_mode": instance.sync_mode.value,
        "is_demo": is_demo_instance(instance.config, instance.sync_mode.value),
        "schedule_cron": instance.schedule_cron,
        "last_run_status": last_status,
        "last_run_at": last_run_at.isoformat() if last_run_at is not None else None,
        "last_success_at": last_success_at.isoformat() if last_success_at else None,
        "health": health,
        "last_run_object_counts": last_run.object_counts if last_run else {},
        "secrets": secrets,
        "detail_path": f"/connectors/{instance.id}",
    }


def _instance_detail(db: Session, instance: ConnectorInstance) -> dict:
    summary = _instance_summary(db, instance)
    connector_row = db.get(Connector, instance.connector_id)
    return {
        **summary,
        "config": instance.config or {},
        "config_fields": (
            declared_config_fields(connector_row, instance.auth_method.value) if connector_row is not None else []
        ),
    }


@router.get("/connector-instances/health")
def connector_instances_health(
    health: str | None = Query(
        default=None,
        description="Filter: healthy | stale | failed | never | running",
    ),
    stale_after_hours: int | None = Query(
        default=None,
        description=f"Hours after which a successful sync is stale (default {DEFAULT_STALE_AFTER_HOURS}).",
    ),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Integration health: summary counts + per-instance freshness."""
    try:
        return connector_health_center(
            db,
            org.id,
            health=health,
            stale_after_hours=stale_after_hours,
        )
    except ConnectorHealthError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/connector-instances")
def list_connector_instances(db: Session = Depends(get_db), org: Organization = Depends(get_current_org)) -> list[dict]:
    if expire_stale_running_runs(db, org_id=org.id):
        db.commit()
    instances = db.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org.id)).all()
    return [_instance_summary(db, i) for i in instances]


@router.get("/connector-instances/{connector_instance_id}")
def get_connector_instance(
    connector_instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Instance detail for the Builder edit UI: config + secret field status (no plaintext)."""
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    return _instance_detail(db, instance)


class ConnectorInstanceIn(BaseModel):
    """Create a connector instance.

    Preferred (UI) shape: `connector_name` + `display_name` +
    `external_tenant_ref` — creates inventory rows and ensures the catalog
    entry from the installed package.

    Legacy shape: `connector_id` + `application_instance_id` — attach to an
    already-seeded inventory row (still used by tests and CLI-adjacent flows).

    Optional `secrets` are envelope-encrypted immediately; never returned.
    """

    connector_name: str | None = None
    connector_id: uuid.UUID | None = None
    application_instance_id: uuid.UUID | None = None
    display_name: str | None = None
    external_tenant_ref: str | None = None
    config: dict = {}
    auth_method: str
    sync_mode: str = "fixtures"
    schedule_cron: str | None = None
    secrets: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _require_identity(self) -> ConnectorInstanceIn:
        if self.connector_name:
            if not self.display_name and self.application_instance_id is None:
                raise ValueError("display_name is required when creating via connector_name")
            if self.application_instance_id is None and not (self.external_tenant_ref and self.external_tenant_ref.strip()):
                raise ValueError("external_tenant_ref is required when creating a new application instance")
            return self
        if self.connector_id is not None and self.application_instance_id is not None:
            return self
        raise ValueError(
            "Provide connector_name (with display_name / external_tenant_ref), or connector_id + application_instance_id"
        )


def _apply_create_secrets(
    db: Session,
    *,
    org_id: uuid.UUID,
    instance: ConnectorInstance,
    secrets: dict[str, str],
    sync_mode: str,
) -> None:
    connector_row = db.get(Connector, instance.connector_id)
    if connector_row is None:
        raise HTTPException(status_code=500, detail="Connector instance references an unknown connector")
    require_all = sync_mode == SyncMode.LIVE.value
    if secrets or require_all:
        try:
            upsert_secrets(
                db,
                org_id=org_id,
                instance=instance,
                connector=connector_row,
                secrets=secrets,
                require_all_declared=require_all,
            )
        except ConnectorAuthoringError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


def _require_live_secrets_present(db: Session, body: ConnectorInstanceIn) -> None:
    """Fail fast before creating inventory rows when live secrets are incomplete."""
    if body.sync_mode != SyncMode.LIVE.value:
        return
    connector_name = body.connector_name
    if connector_name is None and body.connector_id is not None:
        row = db.get(Connector, body.connector_id)
        connector_name = row.name if row else None
    if not connector_name:
        return
    discovered = discover_connectors()
    reg = discovered.get(connector_name)
    if reg is None:
        return
    manifest = reg.connector_class.manifest
    declared: list[str] = []
    for method in manifest.auth_methods:
        if method.id == body.auth_method:
            declared = list(method.secret_fields)
            break
    if not declared:
        declared = sorted(manifest.secret_field_names())
    missing = [f for f in declared if not (body.secrets.get(f) or "").strip()]
    if missing:
        raise HTTPException(
            status_code=400,
            detail="Live mode requires secrets for: " + ", ".join(missing),
        )


@router.post("/connector-instances", status_code=201)
def create_connector_instance_route(
    body: ConnectorInstanceIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    _require_live_secrets_present(db, body)

    if body.connector_name:
        try:
            instance = create_connector_instance(
                db,
                org_id=org.id,
                connector_name=body.connector_name,
                display_name=body.display_name or "",
                external_tenant_ref=body.external_tenant_ref or "",
                config=body.config,
                auth_method=body.auth_method,
                sync_mode=body.sync_mode,
                schedule_cron=body.schedule_cron,
                application_instance_id=body.application_instance_id,
            )
        except ConnectorAuthoringError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        # Legacy path: operator already has catalog + application instance ids.
        assert body.connector_id is not None and body.application_instance_id is not None
        try:
            validate_connector_config_urls(body.config, require_https=body.sync_mode != SyncMode.FIXTURES.value)
            reject_secrets_in_config(body.config)
        except UnsafeConnectorURLError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ConnectorAuthoringError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if body.schedule_cron is not None:
            try:
                validate_cron(body.schedule_cron)
            except InvalidCronError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        connector_row = db.get(Connector, body.connector_id)
        if connector_row is None:
            raise HTTPException(status_code=400, detail="Unknown connector_id")
        app_instance = db.get(ApplicationInstance, body.application_instance_id)
        if app_instance is None or app_instance.org_id != org.id:
            raise HTTPException(status_code=400, detail="application_instance not found in this organization")

        try:
            auth = AuthMethod(body.auth_method)
            mode = SyncMode(body.sync_mode)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        instance = ConnectorInstance(
            id=uuid.uuid4(),
            org_id=org.id,
            connector_id=body.connector_id,
            application_instance_id=body.application_instance_id,
            config=body.config,
            auth_method=auth,
            sync_mode=mode,
            schedule_cron=body.schedule_cron,
        )
        db.add(instance)
        db.flush()

    _apply_create_secrets(
        db,
        org_id=org.id,
        instance=instance,
        secrets=body.secrets,
        sync_mode=body.sync_mode,
    )

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.created",
        target_type="connector_instance",
        target_id=instance.id,
        context={
            "connector_name": body.connector_name,
            "schedule_cron": body.schedule_cron,
            "secrets_fields_set": sorted(body.secrets.keys()) if body.secrets else [],
        },
    )
    db.commit()
    return _instance_summary(db, instance)


@router.delete("/connector-instances/{connector_instance_id}", status_code=200)
def delete_connector_instance_route(
    connector_instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Delete a connector instance and everything collected through it.

    Removes secrets, cursors, run history, the instance row, and the entities,
    graph rows, snapshots, change events, and findings of the bound
    application instance. The application instance itself is removed too
    unless another connector instance is still bound to it. Inventory cannot be
    kept: every inventory row references the run that produced it.
    """
    try:
        summary = delete_connector_instance(
            db,
            org_id=org.id,
            connector_instance_id=connector_instance_id,
        )
    except ConnectorDeleteError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.deleted",
        target_type="connector_instance",
        target_id=connector_instance_id,
        context={
            "application_instance_id": summary.get("application_instance_id"),
            "application_instance_deleted": summary.get("application_instance_deleted"),
            "runs_deleted": summary.get("runs_deleted"),
        },
    )
    db.commit()
    return {"ok": True, **summary}


class ConnectorInstanceUpdateIn(BaseModel):
    config: dict | None = None
    auth_method: str | None = None
    sync_mode: str | None = None
    display_name: str | None = None
    # Re-entered credentials. Required in practice whenever a URL / host
    # config field changes: the stored secrets are cleared on such a change
    # and only what arrives here is kept.
    secrets: dict[str, str] | None = None


@router.patch("/connector-instances/{connector_instance_id}")
def update_connector_instance(
    connector_instance_id: uuid.UUID,
    body: ConnectorInstanceUpdateIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Update non-secret settings (config / auth / sync mode / display name).

    Changing a field that decides where requests go (``org_url``,
    ``base_url``, any ``*_url`` / ``*_host`` / ``*_domain`` key, or any
    URL-valued key) clears the instance's stored secrets: otherwise anyone
    allowed to edit config could point the connector at their own server and
    collect the credential on the next test or sync. Secrets supplied in the
    same request are stored after the clear. The response lists the cleared
    fields in ``secrets_cleared`` and sets ``secrets_reentry_required`` so the
    UI can ask for them again.
    """
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")

    new_sync_mode: SyncMode | None = None
    if body.sync_mode is not None:
        try:
            new_sync_mode = SyncMode(body.sync_mode)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    effective_sync_mode = new_sync_mode or instance.sync_mode
    require_https = effective_sync_mode != SyncMode.FIXTURES

    endpoint_changes: list[str] = []
    if body.config is not None:
        try:
            validate_connector_config_urls(body.config, require_https=require_https)
            reject_secrets_in_config(body.config)
        except UnsafeConnectorURLError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ConnectorAuthoringError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        endpoint_changes = changed_endpoint_fields(instance.config, body.config)
        instance.config = body.config
    elif new_sync_mode is not None and require_https and instance.sync_mode == SyncMode.FIXTURES:
        # Going live with a config saved under fixtures: hold it to the live rules.
        try:
            validate_connector_config_urls(instance.config or {}, require_https=True)
        except UnsafeConnectorURLError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if body.auth_method is not None:
        try:
            instance.auth_method = AuthMethod(body.auth_method)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if new_sync_mode is not None:
        instance.sync_mode = new_sync_mode

    if body.display_name is not None:
        name = body.display_name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="display_name cannot be empty")
        app_instance = db.get(ApplicationInstance, instance.application_instance_id)
        if app_instance is None or app_instance.org_id != org.id:
            raise HTTPException(status_code=400, detail="application_instance not found")
        app_instance.display_name = name

    removed: list[str] = []
    if endpoint_changes:
        removed = delete_secrets(db, connector_instance_id=instance.id)

    secrets_set: list[str] = []
    if body.secrets:
        connector_row = db.get(Connector, instance.connector_id)
        if connector_row is None:
            raise HTTPException(status_code=500, detail="Connector instance references an unknown connector")
        try:
            upsert_secrets(
                db,
                org_id=org.id,
                instance=instance,
                connector=connector_row,
                secrets=body.secrets,
                require_all_declared=False,
            )
        except ConnectorAuthoringError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        secrets_set = sorted(k for k, v in body.secrets.items() if isinstance(v, str) and v.strip())
    secrets_cleared = [f for f in removed if f not in secrets_set]

    db.flush()
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.updated",
        target_type="connector_instance",
        target_id=instance.id,
        context={
            "config_updated": body.config is not None,
            "auth_method": body.auth_method,
            "sync_mode": body.sync_mode,
            "display_name_updated": body.display_name is not None,
            "endpoint_fields_changed": endpoint_changes,
            "secrets_cleared": secrets_cleared,
            "secrets_fields_set": secrets_set,
        },
    )
    db.commit()
    return {
        **_instance_detail(db, instance),
        "endpoint_fields_changed": endpoint_changes,
        "secrets_cleared": secrets_cleared,
        "secrets_reentry_required": bool(secrets_cleared),
    }


class ConnectorSecretsIn(BaseModel):
    secrets: dict[str, str] = Field(default_factory=dict)


@router.get("/connector-instances/{connector_instance_id}/secrets")
def get_connector_instance_secrets(
    connector_instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Secret field status only — never plaintext or ciphertext."""
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    connector_row = db.get(Connector, instance.connector_id)
    if connector_row is None:
        raise HTTPException(status_code=500, detail="Connector instance references an unknown connector")
    return secret_status(db, connector=connector_row, instance=instance)


@router.put("/connector-instances/{connector_instance_id}/secrets")
def put_connector_instance_secrets(
    connector_instance_id: uuid.UUID,
    body: ConnectorSecretsIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Upsert envelope-encrypted secrets. Empty values are ignored (leave blank to keep)."""
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    connector_row = db.get(Connector, instance.connector_id)
    if connector_row is None:
        raise HTTPException(status_code=500, detail="Connector instance references an unknown connector")

    try:
        status = upsert_secrets(
            db,
            org_id=org.id,
            instance=instance,
            connector=connector_row,
            secrets=body.secrets,
            require_all_declared=False,
        )
    except ConnectorAuthoringError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.secrets_updated",
        target_type="connector_instance",
        target_id=instance.id,
        context={"fields_set": sorted(k for k, v in body.secrets.items() if isinstance(v, str) and v.strip())},
    )
    db.commit()
    return status


class ConnectorInstanceScheduleIn(BaseModel):
    schedule_cron: str | None = None


@router.patch("/connector-instances/{connector_instance_id}/schedule")
def set_connector_instance_schedule(
    connector_instance_id: uuid.UUID,
    body: ConnectorInstanceScheduleIn,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Sets or clears (schedule_cron: null) an instance's periodic sync
    schedule. The worker's dispatcher (kestrel.schedule.dispatch_scheduled_syncs)
    polls schedule_cron once a minute; see docs/operations/scheduled-syncs.md."""
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")

    if body.schedule_cron is not None:
        try:
            validate_cron(body.schedule_cron)
        except InvalidCronError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    instance.schedule_cron = body.schedule_cron
    db.flush()
    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.schedule_updated",
        target_type="connector_instance",
        target_id=instance.id,
        context={"schedule_cron": body.schedule_cron},
    )
    db.commit()
    return _instance_summary(db, instance)


@router.post("/connector-instances/{connector_instance_id}/test-connection")
def test_connector_connection(
    connector_instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Probe live/fixture credentials via collector.health_check().

    Does not start a full sync or write inventory. Secrets are never returned.
    """
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")

    try:
        result = probe_connector_instance(db, instance)
    except ConnectorProbeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.connection_tested",
        target_type="connector_instance",
        target_id=instance.id,
        context={
            "ok": result.get("ok"),
            "healthy": result.get("healthy"),
            "sync_mode": result.get("sync_mode"),
            "auth_method": result.get("auth_method"),
        },
    )
    db.commit()
    return result


class ProbeConnectorConfigRequest(BaseModel):
    connector_name: str = Field(min_length=1, max_length=100)
    auth_method: str = Field(default="pat", max_length=50)
    sync_mode: str = Field(default="live", pattern="^(live|fixtures)$")
    config: dict = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)


@router.post("/connectors/probe")
def probe_connector_before_save(
    body: ProbeConnectorConfigRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
) -> dict:
    """Test credentials the wizard has not saved yet.

    Runs the connector's health check against the supplied config + secrets
    and returns the classified result and the per-permission checklist. The
    secrets are held in memory for the duration of the call only; the audit
    event records the outcome, never the inputs.
    """
    try:
        result = probe_connector_config(
            connector_name=body.connector_name,
            config=body.config,
            auth_method=body.auth_method,
            sync_mode=body.sync_mode,
            secrets=body.secrets or None,
        )
    except ConnectorProbeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector.config_probed",
        target_type="connector",
        target_id=None,
        context={
            "connector_name": body.connector_name,
            "ok": result.get("ok"),
            "sync_mode": result.get("sync_mode"),
            "auth_method": result.get("auth_method"),
        },
    )
    db.commit()
    return result


@router.post("/connector-instances/{connector_instance_id}/sync", status_code=202)
def trigger_sync(
    connector_instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    actor: Operator = Depends(require_role(OperatorRole.ANALYST)),
    tasks: TaskQueue = Depends(get_task_queue),
) -> dict:
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")

    task_id = enqueue_instance_sync(db, instance, tasks)

    record_audit_event(
        db,
        org_id=org.id,
        actor_operator_id=actor.id,
        action="connector_instance.sync_triggered",
        target_type="connector_instance",
        target_id=instance.id,
        context={"task_id": task_id},
    )
    db.commit()

    return {"enqueued": True, "task_id": task_id}


@router.get("/connector-instances/{connector_instance_id}/runs")
def list_runs(
    connector_instance_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
    limit: int = Query(200, ge=1, le=200),
) -> list[dict]:
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org.id:
        raise HTTPException(status_code=404, detail="Connector instance not found")

    runs = db.scalars(
        select(ConnectorRun)
        .where(ConnectorRun.connector_instance_id == instance.id)
        .order_by(ConnectorRun.started_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": r.id,
            "status": r.status.value,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "object_counts": r.object_counts,
            "error_summary": r.error_summary,
            "triggered_by": r.triggered_by.value,
            "detail_path": f"/connectors/runs/{r.id}",
        }
        for r in runs
    ]


@router.get("/connector-runs/{run_id}")
def get_connector_run(
    run_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Sync run detail: object counts, errors, drift summary, and policy evaluations."""
    detail = connector_run_detail(db, org.id, run_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Connector run not found")
    previous = detail.get("previous_successful_run")
    previous_out = None
    if previous is not None:
        previous_out = {
            **previous,
            "id": str(previous["id"]),
        }
    return {
        **detail,
        "id": str(detail["id"]),
        "previous_successful_run": previous_out,
        "connector_instance": {
            **detail["connector_instance"],
            "id": str(detail["connector_instance"]["id"]),
            "connector_id": str(detail["connector_instance"]["connector_id"]),
        },
        "application": {
            **detail["application"],
            "id": str(detail["application"]["id"]) if detail["application"]["id"] else None,
        },
        "policy_evaluations": [
            {
                **ev,
                "id": str(ev["id"]),
                "policy_id": str(ev["policy_id"]),
            }
            for ev in detail["policy_evaluations"]
        ],
    }


@router.get("/connector-runs/{run_id}/changes")
def get_connector_run_changes(
    run_id: uuid.UUID,
    change_type: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_org),
) -> dict:
    """Entity drift / change diff for a sync run."""
    try:
        payload = list_run_changes(
            db,
            org.id,
            run_id,
            change_type=change_type,
            entity_type=entity_type,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if payload is None:
        raise HTTPException(status_code=404, detail="Connector run not found")

    previous = payload.get("previous_successful_run")
    previous_out = None
    if previous is not None:
        previous_out = {**previous, "id": str(previous["id"])}

    return {
        **payload,
        "run_id": str(payload["run_id"]),
        "previous_successful_run": previous_out,
        "changes": [
            {
                **row,
                "id": str(row["id"]),
                "entity_id": str(row["entity_id"]),
            }
            for row in payload["changes"]
        ],
    }
