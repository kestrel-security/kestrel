# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Orchestrates one full connector sync: creates a ConnectorRun, runs the
SDK collector/normalizer, upserts entities, writes the graph, diffs events,
and marks the run's outcome. This is what the worker's Celery task and
`kestrel sync` both call -- neither talks to the SDK runner directly.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from kestrel.connectors.sdk.base import Connector, Transport
from kestrel.connectors.sdk.runner import run_collection
from kestrel.db.locks import IDENTITY_CORRELATION, org_advisory_xact_lock
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import Event
from kestrel.graph.writer import (
    delete_stale_edges,
    delete_tombstoned_nodes,
    upsert_edges,
    upsert_nodes,
    write_identity_link_edges,
)
from kestrel.observability.metrics import observe_sync_run
from kestrel.observability.tracing import get_tracer
from kestrel.sync.cursors import advance_cursors, incremental_object_types, load_since_by_object_type, with_initial_lookback
from kestrel.sync.upsert import UpsertContext, detect_deletions, upsert_provenance_objects, upsert_relationship_objects

logger = logging.getLogger(__name__)

# A collector's `skipped_object_types` reason that is information, not a gap.
# ``not_configured`` means the provider had nothing to return (an org without
# SAML SSO has no SAML identities): every row the family would have refreshed
# does not exist, so absence proves exactly what it says. It is kept on the run
# so the operator sees why, but it must not degrade the run -- doing so turned
# every non-SSO GitHub org permanently PARTIAL, with deletion detection and
# snapshots switched off for good.
#
# ``*.truncated`` notes (GitHub's deep-scan cap, Slack's channel-membership
# cap) are deliberately *not* here. A cap leaves real rows past it unrefreshed,
# and deletion detection works by absence across every kind of the application
# instance, so a truncated family's rows would be tombstoned as deleted.
INFORMATIONAL_SKIP_REASONS = frozenset({"not_configured"})


def coverage_gaps(skipped_object_types: dict[str, str]) -> dict[str, str]:
    """The skips that mean "could not read", as opposed to "nothing to read"."""
    return {name: reason for name, reason in skipped_object_types.items() if reason not in INFORMATIONAL_SKIP_REASONS}


def refresh_identity_correlation(session: Session, *, org_id: uuid.UUID) -> None:
    """Rebuild ``identity_links`` and the MAPS_TO edges projected from them.

    Both are rewritten wholesale for the whole org, so two syncs of different
    connectors in one org doing this at once collide: the second one's DELETE
    cannot see the first one's uncommitted inserts, and its own INSERTs then
    violate the unique keys the first one commits. The per-org advisory lock
    serialises the section; it is held until this transaction ends, and taken
    before the identity rows are read so the rebuild sees the previous
    holder's committed state.
    """
    from kestrel.identities.correlate import rebuild_identity_links

    org_advisory_xact_lock(session, org_id, IDENTITY_CORRELATION)
    rebuild_identity_links(session, org_id=org_id)
    write_identity_link_edges(session, org_id=org_id)


def run_sync(
    session: Session,
    *,
    connector_instance_id: uuid.UUID,
    connector: Connector,
    config: dict,
    secrets: dict[str, str] | None = None,
    transport_override: Transport | None = None,
    triggered_by: ConnectorRunTrigger = ConnectorRunTrigger.MANUAL,
    object_types: list[str] | None = None,
    run_id: uuid.UUID | None = None,
) -> ConnectorRun:
    """Runs one connector sync.

    `object_types` narrows collection to a subset -- how the events-only poll
    picks up audit logs every few minutes without re-walking the directory.
    Such a run is marked `is_incremental`: it is a SUCCESS, because it read
    everything it set out to, but it is not a full inventory, so
    deletion detection and snapshotting are suppressed and it never counts as
    the Changes baseline or as proof a connector is fresh.

    `run_id` names a RUNNING row the caller already committed with
    ``kestrel.sync.execute.start_run`` -- what the worker and ``kestrel sync``
    do, so the run is visible to other sessions (the UI, the 409 guard) while
    it is in progress. Without it the row is created here and only flushed,
    which suits callers that seed and sync in a single transaction.
    """
    instance = session.get(ConnectorInstance, connector_instance_id)
    if instance is None:
        raise ValueError(f"No ConnectorInstance with id {connector_instance_id}")

    run_started_at = datetime.now(UTC)
    monotonic_started = time.monotonic()
    incremental = object_types is not None
    if run_id is not None:
        started = session.get(ConnectorRun, run_id)
        if started is None or started.connector_instance_id != instance.id:
            raise ValueError(f"No ConnectorRun {run_id} for connector instance {connector_instance_id}")
        run = started
        run_started_at = run.started_at or run_started_at
    else:
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=instance.org_id,
            connector_instance_id=instance.id,
            status=ConnectorRunStatus.RUNNING,
            started_at=run_started_at,
            triggered_by=triggered_by,
            is_incremental=incremental,
        )
        session.add(run)
        session.flush()

    tracer = get_tracer("kestrel.sync")
    with tracer.start_as_current_span(
        "kestrel.sync.run",
        attributes={
            "kestrel.connector_instance_id": str(connector_instance_id),
            "kestrel.connector_run_id": str(run.id),
            "kestrel.sync.trigger": triggered_by.value,
            "kestrel.sync.incremental": incremental,
        },
    ) as span:
        try:
            # Live syncs decrypt secrets here — never put plaintext in Celery kwargs.
            # Fixture mode passes transport_override and skips authenticate().
            if transport_override is None and secrets is None:
                from kestrel.secrets.store import get_secrets

                secrets = get_secrets(
                    session,
                    org_id=instance.org_id,
                    connector_instance_id=instance.id,
                )

            # Cursored types with no cursor yet start from a bounded window
            # rather than the provider's whole default history (see cursors).
            since_by_object_type = with_initial_lookback(
                load_since_by_object_type(session, connector_instance_id=instance.id),
                incremental_object_types=incremental_object_types(connector.manifest),
                run_started_at=run_started_at,
            )
            collection = run_collection(
                connector,
                config=config,
                secrets=secrets,
                transport_override=transport_override,
                since_by_object_type=since_by_object_type,
                object_types=object_types,
            )

            ctx = UpsertContext(
                org_id=instance.org_id,
                application_instance_id=instance.application_instance_id,
                connector_run_id=run.id,
                connector_instance_id=instance.id,
                # An app reported with no scopes has lost them only if this
                # run read the whole tenant's scopes. Connectors emit scopes
                # from the same payload as their app, except where scopes are
                # an object type of their own (Slack's ``oauth_scope``).
                reconcile_absent_scopes=not incremental and "oauth_scope" not in collection.skipped_object_types,
            )

            changes = upsert_provenance_objects(session, collection.normalized_objects, ctx)
            session.flush()

            node_id_maps = upsert_nodes(session, collection.normalized_objects, ctx)
            changes.extend(upsert_relationship_objects(session, collection.normalized_objects, ctx))
            session.flush()

            # Operator classification rules read group membership, so they run
            # once both passes have written. The audit-log poll touches neither.
            if any(obj.kind in ("identity", "group_membership") for obj in collection.normalized_objects):
                from kestrel.identities.classification import reclassify_identities

                reclassify_identities(session, instance.org_id)

            upsert_edges(session, collection.normalized_objects, ctx, node_id_maps)
            if ctx.skipped_unresolved:
                skipped = dict(ctx.skipped_unresolved)
                logger.warning(
                    "sync.unresolved_references_skipped: %d relationship(s) pointed at an object this run did not"
                    " collect and were not written (%s); a run that collects both sides writes them",
                    sum(skipped.values()),
                    ", ".join(f"{kind}={count}" for kind, count in sorted(skipped.items())),
                    extra={"connector_run_id": str(run.id), "skipped": skipped},
                )

            # A run that could not read part of the tenant has an incomplete
            # inventory, and deletion detection works by absence -- every row
            # the skipped object type would have refreshed still carries a
            # stale last_seen_at. Running it here would report the entire
            # family as deleted. Suppress it for this run; the next complete
            # run picks up any real disappearance.
            # An incremental run is partial by construction, not by failure:
            # it never looked at the object types it did not collect, so their
            # rows all carry a stale last_seen_at and absence proves nothing.
            gaps = coverage_gaps(collection.skipped_object_types)
            degraded = bool(gaps)
            if not degraded and not incremental:
                changes.extend(detect_deletions(session, ctx, run_started_at))
                # The graph is a derived read-model, so revoked access has to be
                # pruned from it too or Explore keeps drawing the line.
                # No Event: the relationship row's DELETED change above already
                # records the revocation.
                delete_stale_edges(session, ctx, run_started_at)
                delete_tombstoned_nodes(session, ctx, run_started_at)

            # Correlation spans applications, so it is rebuilt after every run
            # that changed the directory -- including a degraded one, whose
            # identities are real even though its absences prove nothing. An
            # incremental run that collected no identities (the audit-log
            # poll) cannot have moved a cluster, so it leaves the org-wide
            # rebuild, and the lock it takes, alone.
            if not incremental or any(obj.kind == "identity" for obj in collection.normalized_objects):
                refresh_identity_correlation(session, org_id=instance.org_id)

            # immutable hashed snapshot alongside row-diff events.
            from kestrel.graph.snapshots import write_graph_snapshot

            if not degraded and not incremental:
                write_graph_snapshot(
                    session,
                    org_id=instance.org_id,
                    application_instance_id=instance.application_instance_id,
                    connector_run_id=run.id,
                    node_id_maps=node_id_maps,
                )

            # age/volume caps for provider audit activity events.
            from kestrel.activity.retention import prune_activity_events

            prune_activity_events(
                session,
                org_id=instance.org_id,
                application_instance_id=instance.application_instance_id,
            )

            for change in changes:
                session.add(
                    Event(
                        id=uuid.uuid4(),
                        org_id=instance.org_id,
                        connector_run_id=run.id,
                        entity_type=change.entity_type,
                        entity_id=change.entity_id,
                        change_type=change.change_type,
                        field_changes=change.field_changes,
                        detected_at=datetime.now(UTC),
                    )
                )

            # Every note is kept for display; only the gaps decide the status.
            run.skipped_object_types = dict(collection.skipped_object_types)
            if degraded:
                run.status = ConnectorRunStatus.PARTIAL_FAILURE
                detail = ", ".join(f"{name} ({reason})" for name, reason in sorted(gaps.items()))
                run.error_summary = (
                    f"Collected with reduced coverage; could not read: {detail}. "
                    "Deletion detection and snapshotting were skipped for this run "
                    "because the inventory is incomplete."
                )[:2000]
            else:
                run.status = ConnectorRunStatus.SUCCESS

            # Only the object types this run actually collected advance, and
            # only to when collection *started* -- anything that happened
            # during the run may not have been visible to it, which is what
            # the overlap window on the next read covers. A degraded family
            # collected nothing, so its watermark must not move past events it
            # never saw.
            advance_cursors(
                session,
                org_id=instance.org_id,
                connector_instance_id=instance.id,
                object_types=[name for name in collection.object_type_counts if name not in collection.skipped_object_types],
                watermark=run_started_at,
            )

            run.object_counts = collection.object_type_counts
            run.finished_at = datetime.now(UTC)
            session.flush()
        except Exception as exc:
            # IntegrityError / flush failures leave the session unusable until
            # rollback; without this the FAILED row never commits and the UI
            # looks stuck on the previous run.
            try:
                session.rollback()
            except SQLAlchemyError:
                # The run is marked FAILED below either way; a rollback that
                # itself fails is worth knowing about but must not mask exc.
                logger.warning("sync.rollback_failed", exc_info=True)
            run = session.get(ConnectorRun, run.id) or run
            run.status = ConnectorRunStatus.FAILED
            # Provider errors repeat request URLs and occasionally headers;
            # never let a token reach the run history.
            from kestrel.secrets.scrub import scrub_text

            run.error_summary = scrub_text(f"{type(exc).__name__}: {exc}", (secrets or {}).values())
            run.finished_at = datetime.now(UTC)
            session.add(run)
            session.flush()
            span.set_attribute("kestrel.sync.status", run.status.value)
            observe_sync_run(
                status=run.status.value,
                trigger=triggered_by.value,
                duration_seconds=time.monotonic() - monotonic_started,
            )
            raise

        span.set_attribute("kestrel.sync.status", run.status.value)
        observe_sync_run(
            status=run.status.value,
            trigger=triggered_by.value,
            duration_seconds=time.monotonic() - monotonic_started,
        )
        return run
