# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel init` -- bootstraps a Kestrel deployment: ensures configuration
exists, applies migrations, creates the single Organization row (one org per
deployment, see ADR-0006), and optionally loads demo data with zero cloud
credentials via the GitHub connector's own bundled fixtures.

It runs in two places. In a source checkout it writes a `.env` from
`.env.example` on first use. In a container, configuration already arrives as
environment variables and the working directory is not writable, so it writes
nothing.

Either way the first admin gets a random password, printed once, unless one is
given explicitly. The published development password is opt-in
(`--dev-password`, checkout only) because a checkout on a reachable host would
otherwise come up with a login anyone can read in this repository.
"""

from __future__ import annotations

import base64
import os
import secrets as pysecrets
import uuid
from pathlib import Path

import typer
from alembic import command
from alembic.config import Config
from alembic.util.exc import CommandError
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from kestrel.auth.dev_credentials import DEFAULT_DEV_ADMIN_EMAIL, DEFAULT_DEV_ADMIN_PASSWORD
from kestrel.auth.passwords import hash_password, validate_password_policy
from kestrel.db.models.application import Application, ApplicationInstance, ApplicationType
from kestrel.db.models.connector import AuthMethod, Connector, ConnectorInstance, ConnectorSource, SyncMode
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.org import Organization
from kestrel.db.session import get_sessionmaker
from kestrel.findings.pipeline import evaluate_all_enabled_policies
from kestrel.policies.packs import install_pack
from kestrel.sync.pipeline import run_sync


def _is_deployment(repo_root: Path) -> bool:
    """True when this is a deployed image rather than a source checkout.

    A container is given `DATABASE_URL` and `KESTREL_MASTER_KEY` by Compose
    or an orchestrator, and has no `.env.example` because it is not a
    checkout. Both conditions matter: a developer who exports those variables
    while working in a checkout still gets checkout behaviour.
    """
    configured = bool(os.environ.get("DATABASE_URL")) and bool(os.environ.get("KESTREL_MASTER_KEY"))
    return configured and not (repo_root / ".env.example").exists()


def _ensure_env_file(repo_root: Path) -> None:
    env_path = repo_root / ".env"
    example_path = repo_root / ".env.example"
    if env_path.exists() or _is_deployment(repo_root):
        return
    if not example_path.exists():
        typer.secho(
            "No .env or .env.example found, and DATABASE_URL / KESTREL_MASTER_KEY are not set.\n"
            "Run this from the repository root, or set both variables in the environment.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    content = example_path.read_text()
    key = base64.b64encode(pysecrets.token_bytes(32)).decode()
    content = content.replace("KESTREL_MASTER_KEY=\n", f"KESTREL_MASTER_KEY={key}\n")
    env_path.write_text(content)
    typer.echo(f"Created {env_path} with a generated KESTREL_MASTER_KEY")


# Where the api image keeps alembic.ini and migrations/. Checked last, so a
# checkout always wins over it.
_IMAGE_APP_DIR = Path("/app")


def _resolve_alembic_ini(repo_root: Path) -> Path | None:
    explicit = os.environ.get("KESTREL_ALEMBIC_INI")
    candidates = [Path(explicit)] if explicit else []
    candidates += [repo_root / "alembic.ini", _IMAGE_APP_DIR / "alembic.ini"]
    return next((path for path in candidates if path.is_file()), None)


def _admin_password_for(repo_root: Path, requested: str | None, *, dev_default: bool = False) -> str | None:
    """The password to bootstrap the first admin with, or None for the local default.

    The default is published in this repository, so it is used only when the
    caller opts in (`dev_default`) and this is a checkout, never a deployment.
    Otherwise an unattended bootstrap mints a random one, which is printed once.
    """
    if requested is not None:
        return requested
    if dev_default and not _is_deployment(repo_root):
        return None
    return pysecrets.token_urlsafe(18)


def _run_migrations(repo_root: Path) -> None:
    alembic_ini = _resolve_alembic_ini(repo_root)
    if alembic_ini is None:
        typer.secho(
            "No alembic.ini found. Run this from the repository root, or set KESTREL_ALEMBIC_INI.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)
    cfg = Config(str(alembic_ini))
    # alembic.ini's `script_location = migrations` is relative to the working
    # directory, which is only the ini's directory when run from a checkout.
    cfg.set_main_option("script_location", str(alembic_ini.parent / "migrations"))
    try:
        command.upgrade(cfg, "head")
    except CommandError as exc:
        # The database's alembic_version points at a revision this checkout does
        # not ship. In practice that means a database created by another branch
        # or checkout, which Alembic reports as a bare "Can't locate revision".
        if "Can't locate revision" not in str(exc):
            raise
        from kestrel.db.session import DATABASE_URL

        target = make_url(DATABASE_URL).render_as_string(hide_password=True)
        typer.secho(
            f"The database at {target} is at a migration revision this checkout does not know ({exc}).\n"
            "It was most likely created by a different branch or checkout of Kestrel.\n"
            "Either point DATABASE_URL at another database, or reset this one (destroys its data):\n"
            "    make db-reset CONFIRM=yes",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1) from exc
    typer.echo("Applied database migrations")


def _get_or_create_org(session: Session, org_name: str | None) -> Organization:
    existing = session.scalars(select(Organization)).first()
    if existing is not None:
        return existing
    name = org_name or "Kestrel"
    slug = name.lower().replace(" ", "-")
    org = Organization(id=uuid.uuid4(), name=name, slug=slug)
    session.add(org)
    session.flush()
    typer.echo(f"Created organization '{org.name}' ({org.slug})")
    return org


def _get_or_create_admin_operator(session: Session, org: Organization, email: str | None, password: str | None) -> bool:
    """Bootstraps the first Operator if the org has none -- otherwise
    `kestrel init` would leave a freshly-migrated deployment with no way to
    log in at all. Returns True when an operator was created."""
    existing = session.scalars(select(Operator).where(Operator.org_id == org.id)).first()
    if existing is not None:
        return False

    admin_email = email or DEFAULT_DEV_ADMIN_EMAIL
    # None means the caller opted into the stable local default (see
    # `_admin_password_for`), so a checkout keeps the same login across rebuilds.
    admin_password = password or DEFAULT_DEV_ADMIN_PASSWORD
    validate_password_policy(admin_password)

    operator = Operator(
        id=uuid.uuid4(),
        org_id=org.id,
        email=admin_email,
        display_name="Admin",
        password_hash=hash_password(admin_password),
        role=OperatorRole.ADMIN,
        is_active=True,
    )
    session.add(operator)
    session.flush()

    typer.echo(f"Created admin operator '{admin_email}'")
    if admin_password == DEFAULT_DEV_ADMIN_PASSWORD:
        typer.secho(
            f"Using default local password '{DEFAULT_DEV_ADMIN_PASSWORD}' "
            "(dev only — change for any shared/production deploy).",
            fg=typer.colors.YELLOW,
        )
    else:
        typer.secho(f"Admin password (shown once): {admin_password}", fg=typer.colors.YELLOW, bold=True)
    return True


def _seed_demo_data(session: Session, org: Organization, repo_root: Path) -> None:
    """Loads demo data via the GitHub connector's bundled fixtures -- no
    live credentials or network access needed, satisfying "load demo data
    without cloud credentials" from the project's definition of done."""
    from kestrel_connector_github.connector import GitHubConnector
    from kestrel_connector_github.fixture_transport import ORG_LOGIN, build_fixture_transport

    application = Application(id=uuid.uuid4(), org_id=org.id, name="GitHub", application_type=ApplicationType.GITHUB)
    session.add(application)
    session.flush()

    app_instance = ApplicationInstance(
        id=uuid.uuid4(),
        org_id=org.id,
        application_id=application.id,
        display_name="Acme Corp GitHub (demo)",
        external_tenant_ref=ORG_LOGIN,
    )
    session.add(app_instance)
    session.flush()

    connector_row = session.scalars(select(Connector).where(Connector.name == "github")).one_or_none()
    if connector_row is None:
        connector_row = Connector(
            id=uuid.uuid4(),
            name="github",
            version=GitHubConnector.manifest.version,
            manifest=GitHubConnector.manifest.model_dump(),
            supported_object_types=[ot.name for ot in GitHubConnector.manifest.object_types],
            source=ConnectorSource.BUILTIN,
        )
        session.add(connector_row)
        session.flush()

    connector_instance = ConnectorInstance(
        id=uuid.uuid4(),
        org_id=org.id,
        connector_id=connector_row.id,
        application_instance_id=app_instance.id,
        config={"org_login": ORG_LOGIN},
        auth_method=AuthMethod.PAT,
        sync_mode=SyncMode.FIXTURES,
    )
    session.add(connector_instance)
    session.flush()

    github_pack_dir = repo_root / "packs" / "github-posture"
    if github_pack_dir.exists():
        install_pack(session, org.id, github_pack_dir)
        typer.echo("Installed packs/github-posture")

    run = run_sync(
        session,
        connector_instance_id=connector_instance.id,
        connector=GitHubConnector(),
        config={"org_login": ORG_LOGIN},
        transport_override=build_fixture_transport(),
    )
    if run.status.value == "success":
        evaluate_all_enabled_policies(session, org_id=org.id, connector_run_id=run.id)
    typer.echo(f"Seeded demo GitHub data (sync {run.status.value}) and evaluated policies")


def init(
    seed: bool = typer.Option(
        False, "--seed", help="Load demo data via the GitHub connector's fixtures -- no credentials needed."
    ),
    org_name: str = typer.Option(
        None, "--org-name", help="Name for the organization, created on first init (default: Kestrel)."
    ),
    admin_email: str = typer.Option(
        DEFAULT_DEV_ADMIN_EMAIL,
        "--admin-email",
        envvar="KESTREL_ADMIN_EMAIL",
        help=f"Email for the bootstrapped admin operator (default: {DEFAULT_DEV_ADMIN_EMAIL}).",
    ),
    admin_password: str | None = typer.Option(
        None,
        "--admin-password",
        envvar="KESTREL_ADMIN_PASSWORD",
        help="Password for the bootstrapped admin. Default: a random one, printed once.",
    ),
    dev_password: bool = typer.Option(
        False,
        "--dev-password",
        help=(
            f"Use the published local development password '{DEFAULT_DEV_ADMIN_PASSWORD}' "
            "(source checkout only; ignored for a deployment). Never on a reachable host."
        ),
    ),
    generate_admin_password: bool = typer.Option(
        False,
        "--generate-admin-password",
        hidden=True,
        help="Deprecated: a random admin password is now the default.",
    ),
) -> None:
    """Bootstrap a deployment: config, migrations, the organization, and the first admin."""
    repo_root = Path.cwd()
    deployed = _is_deployment(repo_root)
    _ensure_env_file(repo_root)
    _run_migrations(repo_root)

    password_was_given = admin_password is not None
    admin_password = _admin_password_for(repo_root, admin_password, dev_default=dev_password and not generate_admin_password)

    session = get_sessionmaker()()
    try:
        org = _get_or_create_org(session, org_name)
        admin_created = _get_or_create_admin_operator(session, org, admin_email, admin_password)
        if seed:
            _seed_demo_data(session, org, repo_root)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    typer.secho("\nKestrel is ready.", fg=typer.colors.GREEN, bold=True)
    typer.echo("Login:")
    typer.echo(f"  Email:    {admin_email or DEFAULT_DEV_ADMIN_EMAIL}")
    if not admin_created:
        typer.echo("  Password: unchanged (an admin already existed; `kestrel operator set-password` resets it)")
    elif admin_password is None:
        typer.echo(f"  Password: {DEFAULT_DEV_ADMIN_PASSWORD}")
    elif password_was_given:
        typer.echo(f"  Password: {admin_password}")
    else:
        typer.echo("  Password: (printed above when the admin was created)")
    if not deployed:
        typer.echo("Next steps:")
        typer.echo("  docker compose up --build   # then visit http://localhost:3010/login")
        typer.echo("  kestrel policy validate examples/policies/my_first_policy.py")
