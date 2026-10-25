# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Engine / sessionmaker construction for the Kestrel schema.

Built lazily and memoized rather than at import time: ``create_engine`` reads
``DATABASE_URL`` from the environment, so an import-time engine freezes that
value before a test (or a CLI that loads a ``.env``) has a chance to set it,
and it makes importing anything that touches the DB layer depend on the URL
being present and well-formed.

The module-level names ``engine``, ``SessionLocal`` and ``DATABASE_URL`` are
still available (via PEP 562 ``__getattr__``) and behave exactly as before --
they now build on first access instead of on import.
"""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

# Host-side default matches docker-compose.yml published port (5433:5432).
# CI sets DATABASE_URL to localhost:5432 (service container). Compose services
# set it to postgres:5432 (Docker DNS). Do not export the Compose .env value
# into a host shell -- that hostname is not resolvable on the host.
DEFAULT_DATABASE_URL = "postgresql+psycopg://kestrel:kestrel_dev@localhost:5433/kestrel"

_engine: Engine | None = None
_sessionmaker: sessionmaker[Session] | None = None


def get_database_url() -> str:
    """The configured database URL, read fresh from the environment."""
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_engine() -> Engine:
    """The process-wide Engine, created on first use and memoized."""
    global _engine
    if _engine is None:
        _engine = create_engine(get_database_url(), pool_pre_ping=True)
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    """The process-wide session factory, created on first use and memoized."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
    return _sessionmaker


def reset_engine() -> None:
    """Dispose the memoized Engine and forget it, so the next call re-reads
    ``DATABASE_URL``. Intended for tests and for entry points that load
    configuration after import."""
    global _engine, _sessionmaker
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _sessionmaker = None


_LAZY_ATTRS = {
    "engine": get_engine,
    "SessionLocal": get_sessionmaker,
    "DATABASE_URL": get_database_url,
}


def __getattr__(name: str) -> Any:
    """Backwards-compatible module attributes.

    ``from kestrel.db.session import SessionLocal`` (and ``engine`` /
    ``DATABASE_URL``) still work; they resolve through the memoized builders
    above on first access instead of being bound at import.
    """
    builder = _LAZY_ATTRS.get(name)
    if builder is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return builder()


def __dir__() -> list[str]:
    return sorted([*globals(), *_LAZY_ATTRS])
