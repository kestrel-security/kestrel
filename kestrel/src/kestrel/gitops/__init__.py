# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""GitOps desired-state: export / plan / apply.

Manages packs, custom policies, connector instances, and policy-scoped
finding exceptions from a YAML manifest. Secrets are never stored in YAML —
only field references. Enforcing repo-as-source-of-truth (UI read-only) is
not implemented; this module is the export / plan / apply workflow.
"""

from __future__ import annotations

from kestrel.gitops.apply import apply_manifest
from kestrel.gitops.diff import PlanResult, compute_plan
from kestrel.gitops.export import export_org_state
from kestrel.gitops.manifest import (
    DesiredState,
    GitOpsError,
    load_manifest,
    resolve_manifest_path,
    write_manifest,
)

__all__ = [
    "DesiredState",
    "GitOpsError",
    "PlanResult",
    "apply_manifest",
    "compute_plan",
    "export_org_state",
    "load_manifest",
    "resolve_manifest_path",
    "write_manifest",
]
