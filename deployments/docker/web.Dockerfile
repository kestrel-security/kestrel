# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# Multi-stage so the runtime image ships only the built app, not pnpm, the
# build toolchain, or dev dependencies. That is both a size and a security
# win: a single-stage build left pnpm and its bundled deps (tar, minimatch,
# glob, cross-spawn, ...) in the final image, which the blocking Trivy gate
# flags as CRITICAL/HIGH even though none of it is needed to serve requests
#.

FROM node:22-slim AS builder

RUN corepack enable

# Next.js sends anonymous usage telemetry from `next build` unless told not to.
# Kestrel collects none and builds should not phone home either.
ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web ./apps/web

RUN pnpm install --frozen-lockfile

WORKDIR /app/apps/web
RUN pnpm build


FROM node:22-slim AS runner

WORKDIR /app

# Pick up Debian security updates published since the base image was built;
# the nightly Trivy gate fails on fixed CRITICAL/HIGH OS CVEs.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# The base image bundles npm, which the runtime never uses -- it starts the
# app with `node server.js`. npm's own vendored dependencies (tar, sigstore,
# brace-expansion, picomatch) are the only remaining CRITICAL/HIGH findings
# in this image, so dropping npm removes them along with the unused surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Bind all interfaces so the container is reachable from outside it; Next's
# standalone server defaults to localhost only.
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

# Run as the node image's built-in unprivileged user rather than root.
USER node

# `output: "standalone"` (apps/web/next.config.ts) traces the production
# dependencies actually used and emits a self-contained server.js. static/
# and public/ are not included in that trace and must be copied alongside it.
COPY --from=builder --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=node:node /app/apps/web/public ./apps/web/public

LABEL org.opencontainers.image.source="https://github.com/kestrel-security/kestrel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="kestrel-web" \
      org.opencontainers.image.description="Kestrel web UI (Next.js standalone server)"

EXPOSE 3000

# /login renders without a session or an API call, so it reflects only whether
# the server is up. npm is removed above; node's own fetch does the request.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/login').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

CMD ["node", "apps/web/server.js"]
