# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel demo up|change|down` — fixture-backed demo.

Wraps init + fixture sync + pack install so operators get findings without
cloud credentials. `change` re-syncs edited copies of the same tenants so the
change feed has something real to show. `down` removes fixture-mode demo
connector instances only (does not drop the org or operators).

Four tenants are seeded (GitHub, Slack, Okta, and Google Workspace) so the
demo can show both SaaS privilege drift and an IdP admin spine without live
credentials. Cross-
connector identity correlation (same email / unique display name) collapses
accounts in Explore so one person shows access across all synced tenants.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kestrel.auth.dev_credentials import DEFAULT_DEV_ADMIN_EMAIL, DEFAULT_DEV_ADMIN_PASSWORD
from kestrel.cli import init as init_cli
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
    ConnectorRun,
    ConnectorRunStatus,
    ConnectorSource,
    SyncMode,
)
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.demo import DEMO_CONFIG_FLAG, DEMO_INSTANCE_MARKER
from kestrel.demo.backdate import BASELINE_AGE_DAYS, backdate_run, step_age_days
from kestrel.demo.generate import generate_fixtures
from kestrel.demo.seed_product import seed_product_data
from kestrel.demo.teardown import teardown_application_instances
from kestrel.demo.timeline import TIMELINE, apply_steps, steps_for, tenants_at
from kestrel.findings.pipeline import evaluate_all_enabled_policies
from kestrel.policies.packs import install_pack, retire_missing_packs
from kestrel.sync.pipeline import run_sync

app = typer.Typer(help="Fixture demo: four synthetic tenants, no cloud credentials.")


def _repo_root() -> Path:
    return Path.cwd()


# The development stack publishes the web UI here; a deployment says where it
# lives through APP_URL, the same variable the web container reads.
_DEV_WEB_URL = "http://localhost:3010"


def _web_url() -> str:
    return (os.environ.get("APP_URL") or _DEV_WEB_URL).rstrip("/")


def _seeding_policy_runtime() -> None:
    """Evaluate first-party pack policies in-process instead of per-batch subprocesses.

    The subprocess runtime is a security control for *untrusted* policy code,
    and the isolation costs ~5x: one evaluation pass over the generated tenants
    takes ~44s in a subprocess versus ~8s in-process, and the timeline runs
    several passes. Only pack and system policies take the in-process path;
    custom policies in the org (which can loop forever) keep the subprocess
    runtime and its limits. Setting KESTREL_PACK_POLICY_RUNTIME explicitly
    overrides this default.
    """
    os.environ.setdefault("KESTREL_PACK_POLICY_RUNTIME", "restricted")


def _adopt_master_key_from_env_file(repo_root: Path) -> None:
    """Use the checkout's generated master key when the shell has none.

    `.env` is written for the containers (its URLs point at Compose service
    names), so the host CLI deliberately does not load it wholesale. The one
    value a host-side demo needs from it is the master key: without it the
    product seed skips webhooks, ticketing and AI settings, and the demo's
    Settings pages come up empty. Nothing is written back; the variable is set
    for this process only.
    """
    if os.environ.get("KESTREL_MASTER_KEY"):
        return
    env_path = repo_root / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key == "KESTREL_MASTER_KEY" and value.strip():
            os.environ["KESTREL_MASTER_KEY"] = value.strip().strip("\"'")
            typer.echo("Using KESTREL_MASTER_KEY from .env for this run")
            return


def _print_login(email: str, password: str | None) -> None:
    typer.secho("\nDemo ready.", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  Web UI:  {_web_url()}/login")
    if not os.environ.get("APP_URL"):
        typer.echo("  API:     http://localhost:8010/docs")
    typer.echo(f"  Login:   {email}")
    if password:
        typer.echo(f"  Password: {password}")
    elif os.environ.get("APP_URL"):
        typer.echo("  Password: unchanged (the one `kestrel init` printed)")
    else:
        typer.echo(f"  Password: unchanged ('{DEFAULT_DEV_ADMIN_PASSWORD}' on the local dev stack)")
    typer.echo("  Data is fixture-derived; demo instances are labeled “(demo)”.")
    typer.echo("  Tenants: GitHub · Slack · Okta · Google Workspace")
    typer.echo("")
    # The first sync per connector is the baseline that defines "normal", so it
    # is excluded from the Changes feed by design. Saying so here stops the
    # empty page from reading as a bug.
    typer.secho(
        "  /changes is empty until you run `kestrel demo change` — the first sync",
        fg=typer.colors.YELLOW,
    )
    typer.secho(
        "  of each connector is the baseline, so it has nothing to compare against.",
        fg=typer.colors.YELLOW,
    )
    if os.environ.get("APP_URL"):
        # Configuration from the environment means the Docker deployment,
        # which has no Makefile.
        typer.echo("  Next: kestrel demo change")
    else:
        typer.echo("  Next: kestrel demo change   (or `make demo` to do both)")


@app.command("up")
def demo_up(
    admin_email: str = typer.Option(DEFAULT_DEV_ADMIN_EMAIL, "--admin-email", envvar="KESTREL_ADMIN_EMAIL"),
    admin_password: str | None = typer.Option(
        None,
        "--admin-password",
        envvar="KESTREL_ADMIN_PASSWORD",
        help=(
            f"Default: '{DEFAULT_DEV_ADMIN_PASSWORD}' on first bootstrap in a checkout; "
            "random when configuration comes from the environment."
        ),
    ),
    org_name: str = typer.Option("Demo Org", "--org-name"),
) -> None:
    """Bootstrap (if needed), seed GitHub + Slack + Okta + Google Workspace fixtures + packs, print login."""
    repo_root = _repo_root()
    init_cli._ensure_env_file(repo_root)
    _adopt_master_key_from_env_file(repo_root)
    init_cli._run_migrations(repo_root)

    session = get_sessionmaker()()
    printed_password: str | None = None
    try:
        org = init_cli._get_or_create_org(session, org_name)
        existing_admin = session.scalars(select(Operator).where(Operator.org_id == org.id)).first()
        if existing_admin is None:
            pwd = init_cli._admin_password_for(repo_root, admin_password, dev_default=True) or DEFAULT_DEV_ADMIN_PASSWORD
            init_cli._get_or_create_admin_operator(session, org, admin_email, pwd)
            printed_password = pwd
        else:
            # Re-print email so operators know what to use; password not recoverable.
            admin_email = existing_admin.email

        _ensure_demo_seed(session, org, repo_root)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    _print_login(admin_email, printed_password)


def _ensure_connector_instance(session: Session, org: Organization, tenant: _DemoTenant) -> ConnectorInstance:
    """Idempotent application instance + connector instance for one tenant."""
    connector_cls = tenant.connector_class

    demo_instance = session.scalars(
        select(ApplicationInstance)
        .join(Application, Application.id == ApplicationInstance.application_id)
        .where(
            ApplicationInstance.org_id == org.id,
            ApplicationInstance.display_name.contains(DEMO_INSTANCE_MARKER),
            Application.application_type == tenant.application_type,
        )
    ).first()

    if demo_instance is None:
        application = session.scalars(
            select(Application).where(
                Application.org_id == org.id,
                Application.application_type == tenant.application_type,
            )
        ).first()
        if application is None:
            application = Application(
                id=uuid.uuid4(),
                org_id=org.id,
                name=tenant.application_name,
                application_type=tenant.application_type,
            )
            session.add(application)
            session.flush()

        demo_instance = ApplicationInstance(
            id=uuid.uuid4(),
            org_id=org.id,
            application_id=application.id,
            display_name=tenant.display_name,
            external_tenant_ref=tenant.external_tenant_ref,
        )
        session.add(demo_instance)
        session.flush()

    connector_row = session.scalars(select(Connector).where(Connector.name == tenant.connector_name)).one_or_none()
    if connector_row is None:
        connector_row = Connector(
            id=uuid.uuid4(),
            name=tenant.connector_name,
            version=connector_cls.manifest.version,
            manifest=connector_cls.manifest.model_dump(),
            supported_object_types=[ot.name for ot in connector_cls.manifest.object_types],
            source=ConnectorSource.BUILTIN,
        )
        session.add(connector_row)
        session.flush()

    connector_instance = session.scalars(
        select(ConnectorInstance).where(
            ConnectorInstance.org_id == org.id,
            ConnectorInstance.application_instance_id == demo_instance.id,
        )
    ).first()
    if connector_instance is None:
        connector_instance = ConnectorInstance(
            id=uuid.uuid4(),
            org_id=org.id,
            connector_id=connector_row.id,
            application_instance_id=demo_instance.id,
            config=dict(tenant.config),
            auth_method=tenant.auth_method,
            sync_mode=SyncMode.FIXTURES,
        )
        session.add(connector_instance)
        session.flush()
    if not (connector_instance.config or {}).get(DEMO_CONFIG_FLAG):
        connector_instance.config = {**(connector_instance.config or {}), DEMO_CONFIG_FLAG: True}
        session.flush()
    return connector_instance


def _ensure_demo_seed(session: Session, org: Organization, repo_root: Path) -> None:
    """Idempotent fixture tenants + per-app posture packs + baseline sync.

    The tenants are synced from a *generated* fixture tree rather than the
    connectors' bundled ones. Those bundled sets are deliberately small -- they
    are the CI contract artifact -- and a five-person org does not exercise
    search, pagination, or a graph. Generation is seeded, so the dataset is
    identical on every machine and `demo change` can reproduce the same baseline
    without it being persisted anywhere.
    """
    pack_names = (
        "github-posture",
        "okta-posture",
        "gws-posture",
        "slack-posture",
        "cross-app",
    )
    for pack_name in pack_names:
        pack_dir = repo_root / "packs" / pack_name
        if pack_dir.exists():
            installed = install_pack(session, org.id, pack_dir)
            typer.echo(f"Installed packs/{pack_name} ({len(installed)} policies)")
    # `demo down` keeps policies, so a pack deleted from the repo since the
    # last `demo up` would otherwise keep evaluating on every sync.
    retired = retire_missing_packs(session, org.id, repo_root / "packs")
    if retired:
        typer.echo(f"Disabled {retired} policies from packs no longer in packs/")

    _seeding_policy_runtime()
    with tempfile.TemporaryDirectory() as tmp:
        fixture_dirs = generate_fixtures(Path(tmp))
        last_run_id: uuid.UUID | None = None
        baseline_run_ids: list[uuid.UUID] = []
        synced: list[tuple[_DemoTenant, ConnectorInstance]] = []
        for tenant in _demo_tenants():
            connector_instance = _ensure_connector_instance(session, org, tenant)

            # Re-syncing a tenant that already has history would replay the
            # *pristine* baseline over it, silently reverting every drift step
            # `demo change` applied -- the tenant would look untouched and the
            # Changes feed would fill with reversals. Leave existing tenants
            # alone; `demo down` is how you start over.
            already_synced = session.scalar(
                select(func.count())
                .select_from(ConnectorRun)
                .where(
                    ConnectorRun.connector_instance_id == connector_instance.id,
                    ConnectorRun.status.in_([ConnectorRunStatus.SUCCESS, ConnectorRunStatus.PARTIAL_FAILURE]),
                )
            )
            if already_synced:
                typer.echo(
                    f"Skipped {tenant.connector_name}: already has {already_synced} run(s). "
                    "Run `kestrel demo down` first to rebuild it."
                )
                continue

            run = run_sync(
                session,
                connector_instance_id=connector_instance.id,
                connector=tenant.connector_class(),
                config=dict(tenant.config),
                transport_override=tenant.transport_factory(fixture_dirs.get(tenant.connector_name)),
            )
            if run.status.value in {"success", "partial_failure"}:
                last_run_id = run.id
                baseline_run_ids.append(run.id)
                synced.append((tenant, connector_instance))
            counts = run.object_counts or {}
            typer.echo(
                f"Synced {tenant.connector_name} ({run.status.value}): "
                f"{sum(counts.values())} objects across {len(counts)} types"
            )

        # One evaluation pass over the finished tenant set. Evaluating per
        # tenant re-ran every policy over every row it had already seen, so
        # three tenants cost three full passes to reach the same end state.
        if last_run_id is not None:
            evaluate_all_enabled_policies(session, org_id=org.id, connector_run_id=last_run_id)
            typer.echo("Evaluated policies across all tenants")

        # Date the baseline as an install that happened before the drift
        # timeline, so the findings it opens are genuinely old. Without this
        # every finding is minutes old and the dashboard's aging buckets and
        # `open_older_than_days` filter have nothing to separate.
        baseline_at = datetime.now(UTC) - timedelta(days=BASELINE_AGE_DAYS)
        for run_id in baseline_run_ids:
            backdate_run(session, run_id=run_id, occurred_at=baseline_at)

        # ...then leave every connector with a current run, so a demo that
        # stops here does not present four stale connectors.
        _refresh_health_sync(session, [(t, ci, fixture_dirs.get(t.connector_name)) for t, ci in synced])

    # Operator-side data: triage state, notes, exceptions, watchers, tickets,
    # webhooks, extra operators, audit history, and the posture trend. None of
    # it can come from a connector, and without it a dozen working features
    # render as empty states.
    # The seeded team shares the dev password only in a checkout. On a
    # deployment they get no password at all: visible in pickers and history,
    # impossible to sign in as.
    team_password = None if init_cli._is_deployment(repo_root) else DEFAULT_DEV_ADMIN_PASSWORD
    product = seed_product_data(session, org, operator_password=team_password)
    typer.echo(f"Seeded {product.total} operator-side rows across {len(product.created)} tables")
    if team_password:
        typer.echo(f"  demo team accounts sign in with '{team_password}' (local checkout only)")
    else:
        typer.echo("  demo team accounts have no password and cannot sign in")
    for skipped in product.skipped:
        typer.secho(f"  skipped: {skipped}", fg=typer.colors.YELLOW)


@dataclass(frozen=True)
class _DemoTenant:
    """One fixture-backed tenant, seeded by `up` and drifted by `change`."""

    connector_name: str
    application_type: ApplicationType
    application_name: str
    display_name: str
    auth_method: AuthMethod = AuthMethod.PAT
    # Set lazily in _demo_tenants() so importing this module does not require
    # every connector package to be installed.
    config: dict[str, Any] = field(default_factory=dict)
    external_tenant_ref: str = ""
    # The connector class itself, so `.manifest` is readable without instantiating.
    connector_class: type[Any] = object
    transport_factory: Callable[[Path | None], Any] = None  # type: ignore[assignment]
    fixtures_dir: Path = Path()


def _demo_tenants() -> list[_DemoTenant]:
    from kestrel_connector_github.connector import GitHubConnector
    from kestrel_connector_github.fixture_transport import (
        FIXTURES_DIR as GITHUB_FIXTURES,
    )
    from kestrel_connector_github.fixture_transport import (
        ORG_LOGIN,
    )
    from kestrel_connector_github.fixture_transport import (
        build_fixture_transport as github_transport,
    )
    from kestrel_connector_google_workspace.connector import GoogleWorkspaceConnector
    from kestrel_connector_google_workspace.fixture_transport import (
        DOMAIN as GWS_DOMAIN,
    )
    from kestrel_connector_google_workspace.fixture_transport import (
        FIXTURES_DIR as GWS_FIXTURES,
    )
    from kestrel_connector_google_workspace.fixture_transport import (
        build_fixture_transport as gws_transport,
    )
    from kestrel_connector_okta.connector import OktaConnector
    from kestrel_connector_okta.fixture_transport import (
        FIXTURES_DIR as OKTA_FIXTURES,
    )
    from kestrel_connector_okta.fixture_transport import (
        ORG_URL as OKTA_ORG_URL,
    )
    from kestrel_connector_okta.fixture_transport import (
        build_fixture_transport as okta_transport,
    )
    from kestrel_connector_slack.connector import SlackConnector
    from kestrel_connector_slack.fixture_transport import (
        FIXTURES_DIR as SLACK_FIXTURES,
    )
    from kestrel_connector_slack.fixture_transport import (
        TEAM_ID,
    )
    from kestrel_connector_slack.fixture_transport import (
        build_fixture_transport as slack_transport,
    )

    return [
        _DemoTenant(
            connector_name="github",
            application_type=ApplicationType.GITHUB,
            application_name="GitHub",
            display_name=f"Acme Corp GitHub {DEMO_INSTANCE_MARKER}",
            config={"org_login": ORG_LOGIN},
            external_tenant_ref=ORG_LOGIN,
            connector_class=GitHubConnector,
            transport_factory=lambda d: github_transport(ORG_LOGIN, fixtures_dir=d),
            fixtures_dir=GITHUB_FIXTURES,
        ),
        _DemoTenant(
            connector_name="slack",
            application_type=ApplicationType.SLACK,
            application_name="Slack",
            display_name=f"Acme Workspace Slack {DEMO_INSTANCE_MARKER}",
            config={"team_id": TEAM_ID},
            external_tenant_ref=TEAM_ID,
            auth_method=AuthMethod.OAUTH,
            connector_class=SlackConnector,
            transport_factory=lambda d: slack_transport(TEAM_ID, fixtures_dir=d),
            fixtures_dir=SLACK_FIXTURES,
        ),
        _DemoTenant(
            connector_name="google_workspace",
            application_type=ApplicationType.GOOGLE_WORKSPACE,
            application_name="Google Workspace",
            display_name=f"Acme Google Workspace {DEMO_INSTANCE_MARKER}",
            config={"domain": GWS_DOMAIN},
            external_tenant_ref=GWS_DOMAIN,
            auth_method=AuthMethod.OAUTH,
            connector_class=GoogleWorkspaceConnector,
            transport_factory=lambda d: gws_transport(GWS_DOMAIN, fixtures_dir=d),
            fixtures_dir=GWS_FIXTURES,
        ),
        _DemoTenant(
            connector_name="okta",
            application_type=ApplicationType.OKTA,
            application_name="Okta",
            display_name=f"Acme Okta {DEMO_INSTANCE_MARKER}",
            config={"org_url": OKTA_ORG_URL},
            external_tenant_ref=OKTA_ORG_URL,
            auth_method=AuthMethod.PAT,
            connector_class=OktaConnector,
            transport_factory=lambda d: okta_transport(OKTA_ORG_URL, fixtures_dir=d),
            fixtures_dir=OKTA_FIXTURES,
        ),
    ]


def _refresh_health_sync(
    session: Session,
    jobs: Sequence[tuple[_DemoTenant, ConnectorInstance, Path | None]],
) -> None:
    """Re-sync each tenant at the real clock so connector health is not stale.

    Every run the demo creates is backdated -- the baseline by
    `BASELINE_AGE_DAYS`, the newest timeline step by `NEWEST_STEP_AGE_DAYS` --
    and both are older than the 24-hour staleness threshold in
    `kestrel.connectors.health`. A freshly seeded demo therefore showed four
    `stale` connectors and a dashboard reading "Integrations healthy 0/4",
    which reads as a broken product rather than as a deliberately dated
    timeline.

    This replays the state each tenant is already in and leaves the run at its
    real timestamp. The re-sync is idempotent, so it writes no entity diffs:
    the Changes feed and the finding ages keep the timeline they were given,
    and only "last sync" moves to now. Policies are deliberately not
    re-evaluated, so finding `last_seen_at` stays where `backdate_run` put it.
    """
    for tenant, connector_instance, fixtures in jobs:
        run = run_sync(
            session,
            connector_instance_id=connector_instance.id,
            connector=tenant.connector_class(),
            config=dict(tenant.config),
            transport_override=tenant.transport_factory(fixtures),
        )
        if run.status.value not in {"success", "partial_failure"}:
            typer.secho(
                f"  {tenant.connector_name} health refresh {run.status.value} — connector will read stale",
                fg=typer.colors.YELLOW,
            )
    session.flush()


def _staged_fixtures(connector_name: str, source: Path, target: Path, *, upto: int) -> tuple[Path, list[str]]:
    """Copy the generated fixtures and apply the drift timeline through `upto`.

    Steps are cumulative -- step N assumes 0..N-1 already ran -- so replaying
    from the generated baseline each time is what keeps a multi-step history
    consistent without persisting intermediate trees.

    Only step `upto`'s notes are returned. The earlier steps are replayed to
    rebuild the state, not re-announced: reporting their notes again would make
    every step in the feed look like it repeated everything before it.
    """
    shutil.copytree(source, target)
    apply_steps(target, steps_for(connector_name, upto - 1) if upto else [])
    notes = apply_steps(target, TIMELINE[upto][1].get(connector_name, []))
    return target, notes


@app.command("change")
def demo_change() -> None:
    """Re-sync the demo tenants with staged drift so Changes has real content.

    Run after `demo up`. The first sync is the baseline; this is the second one,
    which is where change detection starts reporting.
    """
    _seeding_policy_runtime()
    session = get_sessionmaker()()
    notes: list[str] = []
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured — run `kestrel demo up` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        tenants = _demo_tenants()
        instances: list[tuple[_DemoTenant, ConnectorInstance]] = []
        for tenant in tenants:
            demo_instance = session.scalars(
                select(ApplicationInstance)
                .join(Application, Application.id == ApplicationInstance.application_id)
                .where(
                    ApplicationInstance.org_id == org.id,
                    ApplicationInstance.display_name.contains(DEMO_INSTANCE_MARKER),
                    Application.application_type == tenant.application_type,
                )
            ).first()
            connector_instance = (
                session.scalars(
                    select(ConnectorInstance).where(
                        ConnectorInstance.org_id == org.id,
                        ConnectorInstance.application_instance_id == demo_instance.id,
                    )
                ).first()
                if demo_instance is not None
                else None
            )
            if connector_instance is not None:
                instances.append((tenant, connector_instance))

        if not instances:
            typer.secho("No demo connector instance — run `kestrel demo up` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        # One sync per timeline step per tenant, oldest first, each backdated so
        # the Changes feed, the finding-age buckets, and the window filters all
        # have a real time axis instead of everything landing "now".
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as tmp:
            # Generation is seeded, so this reproduces exactly the baseline
            # `demo up` synced -- without it every generated identity would
            # diff as deleted.
            generated = generate_fixtures(Path(tmp) / "base")

            for index, (label, _) in enumerate(TIMELINE):
                occurred = now - timedelta(days=step_age_days(index, len(TIMELINE)))
                step_notes: list[str] = []
                step_runs: list[uuid.UUID] = []
                drifting = tenants_at(index)
                for tenant, connector_instance in instances:
                    source = generated.get(tenant.connector_name)
                    if source is None or tenant.connector_name not in drifting:
                        continue
                    staged = Path(tmp) / f"step{index}-{tenant.connector_name}"
                    _, tenant_notes = _staged_fixtures(tenant.connector_name, source, staged, upto=index)
                    run = run_sync(
                        session,
                        connector_instance_id=connector_instance.id,
                        connector=tenant.connector_class(),
                        config=dict(tenant.config),
                        transport_override=tenant.transport_factory(staged),
                    )
                    if run.status.value not in {"success", "partial_failure"}:
                        typer.secho(
                            f"  {tenant.connector_name} sync {run.status.value} — drift not applied",
                            fg=typer.colors.RED,
                        )
                        continue
                    step_runs.append(run.id)
                    step_notes.extend(tenant_notes)

                # Evaluate once per step rather than once per tenant: policies
                # read whole-org state, so a per-tenant call re-scores the other
                # tenants' rows for nothing.
                if step_runs:
                    evaluate_all_enabled_policies(session, org_id=org.id, connector_run_id=step_runs[-1])
                    session.flush()
                    for run_id in step_runs:
                        backdate_run(session, run_id=run_id, occurred_at=occurred)
                if step_notes:
                    notes.append(f"{label} ({occurred.date().isoformat()})")
                    notes.extend(f"  {note}" for note in step_notes)

            # The timeline has left every run backdated. Sync the final state
            # once more at the real clock so the fleet reads healthy without
            # disturbing the history above (see _refresh_health_sync). Staging
            # every tenant at the last step gives each one its end state,
            # including the tenants that stopped drifting earlier.
            final_step = len(TIMELINE) - 1
            refresh: list[tuple[_DemoTenant, ConnectorInstance, Path | None]] = []
            for tenant, connector_instance in instances:
                source = generated.get(tenant.connector_name)
                if source is None:
                    continue
                staged, _ = _staged_fixtures(
                    tenant.connector_name,
                    source,
                    Path(tmp) / f"final-{tenant.connector_name}",
                    upto=final_step,
                )
                refresh.append((tenant, connector_instance, staged))
            _refresh_health_sync(session, refresh)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho("\nStaged tenant drift and re-synced.", fg=typer.colors.GREEN, bold=True)
    for note in notes:
        typer.echo(f"  {note}")
    typer.echo(f"\n  See it: {_web_url()}/changes")


@app.command("down")
def demo_down(
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm teardown without prompt."),
) -> None:
    """Remove the fixture-mode demo tenants labeled (demo) and their data.

    This is a full cascade, because the schema does not allow anything less:
    ``connector_runs.connector_instance_id`` is NOT NULL, and fifteen tables
    carry a NOT NULL run reference back to it, so "remove the connector but keep
    its inventory" is unrepresentable. Everything the demo tenants produced --
    identities, grants, graph, findings, change events -- goes with them.

    The organization, operators, policies, and packs are kept, so `demo up`
    restores a clean tenant without re-bootstrapping the install.
    """
    if not yes:
        confirm = typer.confirm(
            "Remove demo tenants and all data synced from them? Org, operators, and policies are kept.",
            default=False,
        )
        if not confirm:
            raise typer.Abort()

    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.echo("No organization configured.")
            return

        demo_instance_ids = list(
            session.scalars(
                select(ApplicationInstance.id).where(
                    ApplicationInstance.org_id == org.id,
                    ApplicationInstance.display_name.contains(DEMO_INSTANCE_MARKER),
                )
            ).all()
        )
        if not demo_instance_ids:
            typer.echo("No demo application instances found.")
            return

        result = teardown_application_instances(session, org_id=org.id, application_instance_ids=demo_instance_ids)
        session.commit()

        typer.secho(
            f"Removed {result.application_instances} demo tenant(s), "
            f"{result.connector_instances} connector instance(s), "
            f"and {result.total_rows} derived row(s).",
            fg=typer.colors.GREEN,
        )
        for table, count in sorted(result.deleted.items(), key=lambda kv: (-kv[1], kv[0]))[:8]:
            typer.echo(f"  {table}: {count}")
        typer.echo("Re-run `kestrel demo up` to restore.")
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# The shapes the walkthrough depends on. Each is a beat that silently
# disappears if a generator or timeline edit stops producing it, and the
# failure mode without this check is discovering it mid-demo.
_EXPECTED_TENANTS = ("github", "slack", "okta", "google_workspace")
_MIN_IDENTITIES = 150
_MIN_FINDINGS = 50
_MIN_CHANGES = 25
# The default Home board plus the three in `dashboard.presets.BOARD_TEMPLATES`.
_MIN_DASHBOARDS = 4
# `seed_product.TREND_DAYS` writes a 90-day curve; anything much below that is a
# widget with nothing to draw.
_MIN_TREND_POINTS = 30
_ANCHOR_EMAILS = (
    "grace@acme.example.com",
    "ada@acme.example.com",
    "alan@acme.example.com",
    "katherine@acme.example.com",
)
_PROMOTED_EMAIL = "alan@acme.example.com"
_OKTA_SUPER_ADMIN_ROLE = "Super Administrator"
_EXPECTED_POLICY_SLUGS = (
    "cross-app-departed-still-has-access",
    "cross-app-privileged-concentration",
)


@app.command("verify")
def demo_verify() -> None:
    """Check that the demo estate is intact, and fail loudly when it is not.

    Run after `demo up` (and again after `demo change`). Every assertion here
    corresponds to something a presenter shows: four connected tenants, a
    correlated person spanning them, findings including the cross-app ones,
    and a populated Changes feed.
    """
    from kestrel.db.base import is_active
    from kestrel.db.models.access import Grant, Role
    from kestrel.db.models.dashboard import Dashboard
    from kestrel.db.models.event import Event
    from kestrel.db.models.finding import Finding, FindingStatus
    from kestrel.db.models.finding_preset import FindingFilterPreset
    from kestrel.db.models.identity import Identity
    from kestrel.db.models.identity_link import IdentityLink
    from kestrel.db.models.policy import Policy, PolicySource, PolicyVersion
    from kestrel.db.models.posture_trend import PostureTrendSnapshot
    from kestrel.policies.packs import list_available_packs

    session = get_sessionmaker()()
    problems: list[str] = []
    notes: list[str] = []
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured. Run `kestrel demo up` first.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        instances = list(
            session.scalars(
                select(ConnectorInstance)
                .join(ApplicationInstance, ApplicationInstance.id == ConnectorInstance.application_instance_id)
                .where(
                    ConnectorInstance.org_id == org.id,
                    ApplicationInstance.display_name.contains(DEMO_INSTANCE_MARKER),
                )
            ).all()
        )
        connectors_present = set()
        for instance in instances:
            connector = session.get(Connector, instance.connector_id)
            if connector is not None:
                connectors_present.add(connector.name)
        notes.append(f"connectors: {len(instances)} demo instances ({', '.join(sorted(connectors_present))})")
        for expected in _EXPECTED_TENANTS:
            if expected not in connectors_present:
                problems.append(f"no demo tenant for {expected}")

        # Every demo instance must have finished a successful run; a FAILED or
        # missing run is a connector the presenter cannot open.
        for instance in instances:
            latest = session.scalars(
                select(ConnectorRun)
                .where(ConnectorRun.connector_instance_id == instance.id)
                .order_by(ConnectorRun.started_at.desc())
                .limit(1)
            ).first()
            connector = session.get(Connector, instance.connector_id)
            name = connector.name if connector else str(instance.id)
            if latest is None:
                problems.append(f"{name}: no sync run")
            elif latest.status not in {ConnectorRunStatus.SUCCESS, ConnectorRunStatus.PARTIAL_FAILURE}:
                problems.append(f"{name}: last run is {latest.status.value}")

        identity_count = session.scalar(select(func.count()).select_from(Identity).where(Identity.org_id == org.id)) or 0
        notes.append(f"identities: {identity_count}")
        if identity_count < _MIN_IDENTITIES:
            problems.append(f"only {identity_count} identities (expected at least {_MIN_IDENTITIES})")

        for email in _ANCHOR_EMAILS:
            found = session.scalar(
                select(func.count()).select_from(Identity).where(Identity.org_id == org.id, Identity.email == email)
            )
            if not found:
                problems.append(f"anchor persona {email} is missing")

        # The cross-app story: at least one person correlated across three or
        # more applications.
        widest = session.scalar(select(func.max(IdentityLink.member_count)).where(IdentityLink.org_id == org.id)) or 0
        notes.append(f"widest correlated person: {widest} accounts")
        if widest < 3:
            problems.append(f"no person correlated across 3+ applications (widest is {widest})")

        open_findings = (
            session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.org_id == org.id, Finding.status == FindingStatus.OPEN)
            )
            or 0
        )
        notes.append(f"open findings: {open_findings}")
        if open_findings < _MIN_FINDINGS:
            problems.append(f"only {open_findings} open findings (expected at least {_MIN_FINDINGS})")

        for slug in _EXPECTED_POLICY_SLUGS:
            count = (
                session.scalar(
                    select(func.count())
                    .select_from(Finding)
                    .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
                    .join(Policy, Policy.id == PolicyVersion.policy_id)
                    .where(Finding.org_id == org.id, Policy.slug == slug, Finding.status == FindingStatus.OPEN)
                )
                or 0
            )
            notes.append(f"{slug}: {count} open")
            if count == 0:
                problems.append(f"no open finding for {slug} — the cross-app demo beat has no subject")

        # The "Quarterly access drift" beat. The Okta collector reads roles only
        # for users /iam/assignees lists, so a role file alone never lands.
        alan_super_admin = session.scalar(
            select(func.count())
            .select_from(Grant)
            .join(Identity, Identity.id == Grant.identity_id)
            .join(Role, Role.id == Grant.role_id)
            .where(
                Grant.org_id == org.id,
                is_active(Grant),
                Identity.email == _PROMOTED_EMAIL,
                Role.application_instance_id == Identity.application_instance_id,
                Role.name == _OKTA_SUPER_ADMIN_ROLE,
            )
        )
        if not alan_super_admin:
            problems.append(f"{_PROMOTED_EMAIL} holds no Okta {_OKTA_SUPER_ADMIN_ROLE} — the escalation beat is missing")

        # Packs deleted from the repo must not keep evaluating (`demo up` retires them).
        stale = session.scalars(
            select(Policy.pack_name)
            .join(PolicyVersion, PolicyVersion.id == Policy.current_version_id)
            .where(
                Policy.org_id == org.id,
                Policy.source == PolicySource.PACK,
                Policy.pack_name.not_in({pack.name for pack in list_available_packs(_repo_root() / "packs")}),
                PolicyVersion.is_enabled.is_(True),
            )
            .distinct()
        ).all()
        if stale:
            problems.append(f"enabled policies from packs no longer in packs/: {', '.join(sorted(map(str, stale)))}")

        change_count = session.scalar(select(func.count()).select_from(Event).where(Event.org_id == org.id)) or 0
        notes.append(f"change events: {change_count}")
        if change_count < _MIN_CHANGES:
            problems.append(f"only {change_count} change events (run `kestrel demo change`)")

        # Operator-side surfaces the connectors cannot fill. Each of these was
        # an empty page on a freshly seeded demo, which reads as a broken
        # feature rather than as an unused one.
        board_count = session.scalar(select(func.count()).select_from(Dashboard).where(Dashboard.org_id == org.id)) or 0
        notes.append(f"dashboards: {board_count}")
        if board_count < _MIN_DASHBOARDS:
            problems.append(
                f"only {board_count} dashboards (expected at least {_MIN_DASHBOARDS}) — multi-board nav is empty"
            )

        preset_count = (
            session.scalar(select(func.count()).select_from(FindingFilterPreset).where(FindingFilterPreset.org_id == org.id))
            or 0
        )
        notes.append(f"saved finding searches: {preset_count}")
        if preset_count == 0:
            problems.append("no saved finding searches — the Findings favourites row is empty")

        trend_points = (
            session.scalar(
                select(func.count()).select_from(PostureTrendSnapshot).where(PostureTrendSnapshot.org_id == org.id)
            )
            or 0
        )
        notes.append(f"posture trend points: {trend_points}")
        if trend_points < _MIN_TREND_POINTS:
            problems.append(f"only {trend_points} posture trend points — the dashboard trend widget is flat")
    finally:
        session.close()

    for note in notes:
        typer.echo(f"  {note}")
    if problems:
        typer.secho(f"\ndemo verify FAILED ({len(problems)} problems):", fg=typer.colors.RED, bold=True)
        for problem in problems:
            typer.secho(f"  ✗ {problem}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    typer.secho("\ndemo verify OK — the estate has everything the walkthrough shows.", fg=typer.colors.GREEN, bold=True)


@app.command("fallback")
def demo_fallback(
    application: str = typer.Argument(
        ...,
        help="Application type to switch: github, slack, okta, google_workspace, custom, or 'all'.",
    ),
    to: str = typer.Option(..., "--to", help="Which side to make active: 'fixtures' or 'live'."),
) -> None:
    """Switch an application between its live tenant and its fixture twin.

    An unreliable network, an expired token, or a provider outage should not
    end a demo. Where both a live instance and a fixture instance exist for the
    same application, this makes one active and pauses the other: the paused
    instance stops syncing on its schedule and is marked disabled, so it reads
    as deliberately switched off rather than broken.

    Nothing is faked. The fixture side is the same generated estate the offline
    demo uses, and it stays labeled as sample data everywhere it appears; the
    live side keeps its own data untouched and can be switched back.
    """
    target = to.strip().lower()
    if target not in {"fixtures", "live"}:
        typer.secho("--to must be 'fixtures' or 'live'", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    wanted_mode = SyncMode.FIXTURES if target == "fixtures" else SyncMode.LIVE

    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.secho("No organization configured.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        rows = list(
            session.execute(
                select(ConnectorInstance, ApplicationInstance, Application)
                .join(ApplicationInstance, ApplicationInstance.id == ConnectorInstance.application_instance_id)
                .join(Application, Application.id == ApplicationInstance.application_id)
                .where(ConnectorInstance.org_id == org.id)
            ).all()
        )
        wanted_type = application.strip().lower()
        if wanted_type != "all":
            try:
                parsed = ApplicationType(wanted_type)
            except ValueError as exc:
                allowed = ", ".join(t.value for t in ApplicationType)
                typer.secho(f"Unknown application '{application}'. Expected one of: {allowed}, all", fg=typer.colors.RED)
                raise typer.Exit(code=2) from exc
            rows = [row for row in rows if row[2].application_type is parsed]

        if not rows:
            typer.secho(f"No connector instances for '{application}'.", fg=typer.colors.YELLOW)
            raise typer.Exit(code=1)

        by_type: dict[str, list] = {}
        for connector_instance, app_instance, catalog in rows:
            by_type.setdefault(catalog.application_type.value, []).append((connector_instance, app_instance))

        switched = 0
        for app_type, pair in sorted(by_type.items()):
            matching = [(ci, ai) for ci, ai in pair if ci.sync_mode is wanted_mode]
            if not matching:
                typer.secho(
                    f"  {app_type}: no {target} instance to switch to — leaving as is.",
                    fg=typer.colors.YELLOW,
                )
                continue
            for connector_instance, app_instance in pair:
                make_active = connector_instance.sync_mode is wanted_mode
                app_instance.status = ApplicationInstanceStatus.ACTIVE if make_active else ApplicationInstanceStatus.DISABLED
                if not make_active:
                    # A paused instance must not wake up on its own schedule
                    # mid-demo. The expression is remembered so switching back
                    # restores it.
                    if connector_instance.schedule_cron:
                        config = dict(connector_instance.config or {})
                        config["_paused_schedule_cron"] = connector_instance.schedule_cron
                        connector_instance.config = config
                        connector_instance.schedule_cron = None
                else:
                    config = dict(connector_instance.config or {})
                    remembered = config.pop("_paused_schedule_cron", None)
                    if remembered and not connector_instance.schedule_cron:
                        connector_instance.schedule_cron = str(remembered)
                        connector_instance.config = config
                switched += 1
            typer.echo(f"  {app_type}: {target} instance active")
        session.commit()
    finally:
        session.close()

    if switched:
        typer.secho(f"\nSwitched to {target}. Reload the browser to see it.", fg=typer.colors.GREEN)


@app.command("status")
def demo_status() -> None:
    """Which instance is active for each application, live or fixtures."""
    session = get_sessionmaker()()
    try:
        org = session.scalars(select(Organization)).first()
        if org is None:
            typer.echo("No organization configured.")
            return
        rows = list(
            session.execute(
                select(ConnectorInstance, ApplicationInstance, Application)
                .join(ApplicationInstance, ApplicationInstance.id == ConnectorInstance.application_instance_id)
                .join(Application, Application.id == ApplicationInstance.application_id)
                .where(ConnectorInstance.org_id == org.id)
                .order_by(Application.application_type)
            ).all()
        )
        if not rows:
            typer.echo("No connector instances configured.")
            return
        for connector_instance, app_instance, catalog in rows:
            state = "active" if app_instance.status is ApplicationInstanceStatus.ACTIVE else app_instance.status.value
            schedule = connector_instance.schedule_cron or "manual"
            typer.echo(
                f"  {catalog.application_type.value:<18} {connector_instance.sync_mode.value:<9} "
                f"{state:<9} schedule={schedule}  {app_instance.display_name}"
            )
    finally:
        session.close()
