# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim

# Pick up Debian security updates published since the base image was built.
# The nightly Trivy gate fails on fixed CRITICAL/HIGH OS CVEs, and a stale base
# is the usual source of them -- gzip, pcre2, sqlite3, and perl-base all had
# fixes waiting here.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY kestrel ./kestrel
COPY apps/api ./apps/api
COPY packs ./packs
COPY connectors ./connectors

# Connectors are entry-point discovered for GET /connectors (create UI catalog).
#
# uv is a build tool: install it, sync, and remove it in one layer, so it never
# reaches the image. Nothing at runtime calls it, and a scanner reads the
# whole filesystem -- a uv left behind is one more bundled CA store and binary
# to patch (GHSA-hq85-5cpj-mr62). Same uv as CI (.github/workflows, setup-uv)
# and [tool.uv] required-version.
RUN pip install --no-cache-dir --root-user-action=ignore uv==0.12.18 \
    && uv sync --frozen --no-dev --package kestrel-api \
    --package kestrel-connector-github \
    --package kestrel-connector-google-workspace \
    --package kestrel-connector-slack \
    --package kestrel-connector-okta \
    && pip uninstall --yes --root-user-action=ignore uv \
    && rm -rf /root/.cache/uv

# Alembic's config and revision scripts are not part of any installed package,
# but this image doubles as the migration and bootstrap runner (`alembic upgrade
# head`, `kestrel init`, `kestrel operator create`) so a deployment needs no
# fourth image. Copied after `uv sync` so adding a migration does not invalidate
# the dependency layer.
COPY alembic.ini ./
COPY migrations ./migrations

ENV PATH="/app/.venv/bin:$PATH"
ENV KESTREL_PACKS_DIR=/app/packs

# Drop root. Nothing in the API writes to the app tree at runtime -- custom
# policy fixtures live in Postgres (kestrel/policies/custom_fixtures.py) and
# evidence exports are built in memory (kestrel/compliance/evidence_pack.py) --
# so an unwritable /app is a free hardening win.
RUN groupadd --gid 10001 kestrel \
    && useradd --uid 10001 --gid 10001 --create-home kestrel
USER kestrel

LABEL org.opencontainers.image.source="https://github.com/kestrel-security/kestrel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="kestrel-api" \
      org.opencontainers.image.description="Kestrel API: also runs migrations (alembic upgrade head) and bootstrap (kestrel init)"

EXPOSE 8000

# /readyz, not /healthz: it answers only once Postgres and Redis are reachable,
# which is what anything waiting on this container actually needs.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=12 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).status == 200 else 1)"]

CMD ["uvicorn", "kestrel_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
