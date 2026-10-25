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
COPY apps/worker ./apps/worker
COPY connectors ./connectors

# Each bundled connector must be installed explicitly: they are discovered
# via `kestrel.connectors` entry points, so a connector that isn't installed is
# simply invisible to the worker at sync time.
#
# uv is a build tool: install it, sync, and remove it in one layer, so it never
# reaches the image. Nothing at runtime calls it, and a scanner reads the
# whole filesystem -- a uv left behind is one more bundled CA store and binary
# to patch (GHSA-hq85-5cpj-mr62). Same uv as CI (.github/workflows, setup-uv)
# and [tool.uv] required-version.
RUN pip install --no-cache-dir --root-user-action=ignore uv==0.12.18 \
    && uv sync --frozen --no-dev --package kestrel-worker \
    --package kestrel-connector-github \
    --package kestrel-connector-google-workspace \
    --package kestrel-connector-slack \
    --package kestrel-connector-okta \
    && pip uninstall --yes --root-user-action=ignore uv \
    && rm -rf /root/.cache/uv

ENV PATH="/app/.venv/bin:$PATH"

# Drop root. Embedded beat is the one component that needs a writable path (it
# persists its last-run times to a shelve file), and the default location is the
# working directory, which root owns -- hence the dedicated state dir and the
# explicit --schedule below.
RUN groupadd --gid 10001 kestrel \
    && useradd --uid 10001 --gid 10001 --create-home kestrel \
    && mkdir -p /var/lib/kestrel \
    && chown kestrel:kestrel /var/lib/kestrel
USER kestrel

LABEL org.opencontainers.image.source="https://github.com/kestrel-security/kestrel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="kestrel-worker" \
      org.opencontainers.image.description="Kestrel worker: Celery tasks with embedded beat for scheduled syncs"

CMD ["celery", "-A", "kestrel_worker.celery_app", "worker", "--beat", \
     "--schedule", "/var/lib/kestrel/celerybeat-schedule", "-l", "info"]
