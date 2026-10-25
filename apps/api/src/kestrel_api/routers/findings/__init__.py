# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Findings API -- backs the Findings list and investigation workbench UI.

Split by concern into sub-routers, combined here into the one `router` that
`kestrel_api.main` mounts under `/api/v1`:

- `list`: list, ownership queues, saved presets, export, bulk changes.
- `triage`: exceptions, mute/unmute, watchers and digest, tickets, and the
  exception / mute expiry queues.
- `detail`: get, patch, notes, provenance, attack path, blast-radius export,
  handoff, verify.
- `_shared`: helpers more than one sub-router uses.

Mutating routes require at least the analyst role (except watch/unwatch,
which are per-operator); every GET only requires being an authenticated
operator (enforced transitively by get_current_org -> get_current_operator).
`assigned_to` is a real Operator reference, and `created_by` on an exception /
`author` on a note is never client-supplied -- it's always derived from the
authenticated caller.
"""

from __future__ import annotations

from fastapi import APIRouter

from kestrel_api.routers.findings import detail, triage
from kestrel_api.routers.findings import list as list_routes

router = APIRouter()

# Include order is route-match order. Static collection paths (`/findings/queues`,
# `/findings/presets`, `/findings/watched`, `/findings/export`, `/findings/bulk`, ...)
# live in `list` and `triage` and must be registered before `detail`'s
# `/findings/{finding_id}` so a literal segment is never parsed as a finding id.
router.include_router(list_routes.router)
router.include_router(triage.router)
router.include_router(detail.router)
