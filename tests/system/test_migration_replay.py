# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 3 -- migration replay: upgrade -> downgrade -> upgrade on a scratch
database that belongs to this test alone (see ``_scratch_db.py``).

Proves migrations are actually reversible, not just that ``head`` applies
cleanly -- a downgrade script with a typo or a dropped-column-that-should-
have-been-nullable only shows up when it runs.

Two round trips, because they fail differently. One step back catches a
downgrade script with a typo or a column dropped that should have been made
nullable. All the way to ``base`` and up again catches what a per-step replay
cannot: state a downgrade leaves behind. Postgres ENUM types are the case that
actually bit this chain -- dropping a table does not drop the types its columns
used, so the second ``CREATE TYPE`` collided with a type nothing had cleaned
up and the documented rollback path did not work. The initial migration now
drops every type it creates.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from alembic import command
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

_scratch_db_spec = importlib.util.spec_from_file_location(
    "kestrel_tests_system_scratch_db", Path(__file__).resolve().parent / "_scratch_db.py"
)
assert _scratch_db_spec is not None
assert _scratch_db_spec.loader is not None
_scratch_db = importlib.util.module_from_spec(_scratch_db_spec)
_scratch_db_spec.loader.exec_module(_scratch_db)
alembic_config = _scratch_db.alembic_config
scratch_database = _scratch_db.scratch_database


def _current_revision(database_url: str) -> str | None:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            heads = MigrationContext.configure(connection).get_current_heads()
            return heads[0] if heads else None
    finally:
        engine.dispose()


def test_upgrade_downgrade_upgrade_replays_cleanly():
    with scratch_database(label="migrate", migrate=False) as database_url:
        cfg = alembic_config()

        command.upgrade(cfg, "head")
        head_revision = _current_revision(database_url)
        assert head_revision is not None

        command.downgrade(cfg, "-1")
        after_downgrade = _current_revision(database_url)
        assert after_downgrade != head_revision

        command.upgrade(cfg, "head")
        after_reupgrade = _current_revision(database_url)
        assert after_reupgrade == head_revision


def test_downgrade_to_base_and_back_leaves_no_state_behind():
    """The documented rollback path: all the way down, all the way back up.

    A `downgrade base` that leaves ENUM types (or anything else) behind only
    fails on the *second* upgrade, which is exactly the moment an operator is
    rolling forward after a failed release.
    """
    with scratch_database(label="migrate-base", migrate=False) as database_url:
        cfg = alembic_config()

        command.upgrade(cfg, "head")
        head_revision = _current_revision(database_url)
        assert head_revision is not None

        command.downgrade(cfg, "base")
        assert _current_revision(database_url) is None

        command.upgrade(cfg, "head")
        assert _current_revision(database_url) == head_revision


def test_downgrade_to_base_drops_the_enum_types_it_created():
    """The specific leak: no `kestrel` enum type may survive a full downgrade."""
    from sqlalchemy import text

    with scratch_database(label="migrate-enums", migrate=False) as database_url:
        cfg = alembic_config()
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")

        engine = create_engine(database_url)
        try:
            with engine.connect() as connection:
                leftover = (
                    connection.execute(
                        text(
                            "SELECT typname FROM pg_type t "
                            "JOIN pg_namespace n ON n.oid = t.typnamespace "
                            "WHERE t.typtype = 'e' AND n.nspname = 'public' ORDER BY typname"
                        )
                    )
                    .scalars()
                    .all()
                )
        finally:
            engine.dispose()

        assert leftover == [], f"enum types survived downgrade base: {leftover}"


def test_bind_secrets_migration_marks_existing_rows_legacy_and_adds_key_versions():
    """k0f1a2b3c4d5: rows that exist before the upgrade are stamped
    ``key_version = 0`` (legacy, no associated data); tables whose secret is
    optional get a nullable column that is 0 only where a ciphertext exists.
    """
    import json
    import uuid

    from sqlalchemy import MetaData, Table, text

    with scratch_database(label="migrate-secrets", migrate=False) as database_url:
        cfg = alembic_config()
        command.upgrade(cfg, "j9e0f1a2b3c4")

        engine = create_engine(database_url)
        try:
            metadata = MetaData()
            organizations = Table("organizations", metadata, autoload_with=engine)
            endpoints = Table("webhook_endpoints", metadata, autoload_with=engine)
            smtp = Table("org_smtp_settings", metadata, autoload_with=engine)
            assert "secret_key_version" not in endpoints.c
            assert "password_key_version" not in smtp.c

            org_id = uuid.uuid4()
            with_password = uuid.uuid4()
            without_password = uuid.uuid4()
            with engine.begin() as connection:
                connection.execute(organizations.insert().values(id=org_id, name="Legacy Org", slug="legacy-org"))
                connection.execute(
                    endpoints.insert().values(
                        id=uuid.uuid4(),
                        org_id=org_id,
                        name="Legacy",
                        url="https://hooks.example.com/legacy",
                        events=json.dumps(["finding.opened"]),
                        secret_ciphertext=b"ct",
                        secret_nonce=b"nonce",
                        is_enabled=True,
                    )
                )
                connection.execute(
                    smtp.insert().values(
                        id=with_password,
                        org_id=org_id,
                        host="smtp.example.com",
                        port=587,
                        from_address="kestrel@example.com",
                        username="mailer",
                        password_ciphertext=b"ct",
                        password_nonce=b"nonce",
                    )
                )
            # A second org so the unique (org_id) constraint on smtp settings holds.
            other_org = uuid.uuid4()
            with engine.begin() as connection:
                connection.execute(organizations.insert().values(id=other_org, name="Other", slug="other-org"))
                connection.execute(
                    smtp.insert().values(
                        id=without_password,
                        org_id=other_org,
                        host="smtp.example.com",
                        port=25,
                        from_address="kestrel@example.com",
                    )
                )

            command.upgrade(cfg, "head")

            with engine.connect() as connection:
                assert connection.execute(text("SELECT secret_key_version FROM webhook_endpoints")).scalar_one() == 0
                versions = dict(connection.execute(text("SELECT id, password_key_version FROM org_smtp_settings")).all())
                assert versions == {with_password: 0, without_password: None}
                # The server default is gone: an insert must say which key wrote the row.
                default = connection.execute(
                    text(
                        "SELECT column_default FROM information_schema.columns "
                        "WHERE table_name = 'webhook_endpoints' AND column_name = 'secret_key_version'"
                    )
                ).scalar_one()
                assert default is None
        finally:
            engine.dispose()


def test_orm_models_match_the_migrated_schema():
    """`alembic check`: the models and the migration chain must agree, or the
    next `alembic revision --autogenerate` will emit a surprise migration and
    the running schema is not what the code assumes."""
    from alembic.util.exc import AutogenerateDiffsDetected

    with scratch_database(label="migrate-check", migrate=False):
        cfg = alembic_config()
        command.upgrade(cfg, "head")
        try:
            command.check(cfg)
        except AutogenerateDiffsDetected as exc:
            raise AssertionError(f"ORM models drifted from the migrations: {exc}") from exc
