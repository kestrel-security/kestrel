# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "kestrel", "src"))

from kestrel.db import models  # noqa: F401  (registers all tables on Base.metadata)
from kestrel.db.base import Base

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers=False: fileConfig() defaults to True, which
    # silently disables every logger already created at import time. That's
    # harmless for the standalone `alembic upgrade` CLI, but Alembic is also
    # driven in-process (tests that reset the schema, and any future
    # migrate-on-startup path) -- there it would silently mute application
    # loggers that had already been imported, so failures stop being logged
    # with no indication why.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

database_url = os.environ.get("DATABASE_URL", "postgresql+psycopg://kestrel:kestrel_dev@localhost:5433/kestrel")
config.set_main_option("sqlalchemy.url", database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
