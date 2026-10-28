# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Run a draft over edge-case rows to catch code paths fixtures never reach.

A fixture test only exercises the branches its rows take. The draft behind
this module compiled, passed its fixtures (the matching row returned early),
and raised NameError on the first stale row in dry run. Probe rows are the
fixture rows again with each timestamp missing, an ISO string, naive, and
timezone-aware; with the application swapped for another; and with every
optional field left out. Whether a probe row matches is not checked, only that
``policy()`` and ``evidence()`` run on it without raising.
"""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from typing import Any

from kestrel.policies.runtime import (
    CompiledPolicy,
    PolicyCompileError,
    PolicyRuntime,
    RestrictedPythonRuntime,
    compile_and_validate,
    get_default_runtime,
)
from kestrel.policies.testing import expand_relative_timestamps

#: Timestamp fields each resource type's rows carry (see resource_schemas).
#: A ``[]`` segment applies the variant to every element of a list.
TIMESTAMP_PATHS: dict[str, tuple[str, ...]] = {
    "identity": (
        "identity.last_active_at",
        "identity.created_at_source",
        "identity.disabled_at",
        "identity.expires_at",
        "cluster.last_active_at",
        "cluster.accounts[].last_active_at",
        "cluster.accounts[].disabled_at",
    ),
    "event": ("event.occurred_at",),
}

_TIMESTAMP_VARIANTS: tuple[tuple[str, Any], ...] = (
    ("missing", None),
    ("iso-string", "2026-01-02T03:04:05Z"),
    ("naive-datetime", datetime(2026, 1, 2, 3, 4, 5)),
    ("aware-datetime", datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)),
)

#: Fields a policy filters on; the sparse variant keeps them so the policy
#: still reaches the code past its first ``return True``.
_SELECTOR_FIELDS = frozenset(
    {
        "key",
        "action",
        "resource_type",
        "type",
        "name",
        "is_external",
        "is_disabled",
        "identity_type",
        "worker_type",
        "privileged",
        "application_type",
        "idp_status",
        "idp_application_types",
        "idp_connected",
        "representative_identity_id",
        "is_representative",
    }
)
_OTHER_APPLICATION = {"type": "kestrel_probe_other_app", "name": "Other app"}
_PROBE_NAMESPACE = uuid.UUID("6f1d3c2e-4b5a-4e8f-9a7b-0c1d2e3f4a5b")
_NO_ORG = uuid.UUID(int=0)


def _set_path(row: dict[str, Any], path: str, value: Any) -> bool:
    """Set ``path`` on ``row``; ``a.b[].c`` sets ``c`` on every dict in the
    list ``a.b``. Returns False when a list segment is absent or empty, so the
    caller skips a variant that would be identical to the base row."""
    *parents, leaf = path.split(".")
    current: Any = row
    for index, part in enumerate(parents):
        if part.endswith("[]"):
            items = current.get(part[:-2])
            if not isinstance(items, list) or not items:
                return False
            rest = ".".join([*parents[index + 1 :], leaf])
            applied = False
            for item in items:
                if isinstance(item, dict):
                    applied = _set_path(item, rest, value) or applied
            return applied
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[leaf] = value
    return True


def _sparse_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {k: (v if k in _SELECTOR_FIELDS else ([] if isinstance(v, list) else None)) for k, v in value.items()}


def _sparse(row: dict[str, Any]) -> dict[str, Any]:
    """Every optional field missing, as a connector that collects little would
    leave it. ``cluster`` stays structurally valid (``accounts: []``) because
    the loader always builds one; ``org`` is kept as is."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key.startswith("_") or key in ("application", "org"):
            out[key] = value
        elif isinstance(value, dict):
            # cluster included: selector fields such as idp_status and
            # representative_identity_id survive, accounts becomes [].
            out[key] = _sparse_dict(value)
        elif isinstance(value, list):
            out[key] = []
        else:
            out[key] = None
    return out


def probe_rows(fixture_rows: list[dict[str, Any]], resource_type: str | None) -> dict[str, dict[str, Any]]:
    """Edge-case variants of ``fixture_rows`` keyed by a descriptive label.

    Each row's ``_subject_id`` is a UUID derived from its label, since the
    runtimes report matches and errors by subject UUID.
    """
    probes: dict[str, dict[str, Any]] = {}
    paths = TIMESTAMP_PATHS.get(resource_type or "", ())
    for base in fixture_rows:
        base_id = str(base.get("_subject_id") or "row")
        variants: list[tuple[str, dict[str, Any]]] = []
        for path in paths:
            for label, value in _TIMESTAMP_VARIANTS:
                row = copy.deepcopy(base)
                if _set_path(row, path, value):
                    variants.append((f"{path}={label}", row))
        other = copy.deepcopy(base)
        other["application"] = dict(_OTHER_APPLICATION)
        variants.append(("other-application", other))
        variants.append(("sparse", _sparse(copy.deepcopy(base))))
        if isinstance(base.get("cluster"), dict):
            # Rows loaded before correlation ran, and a person with no other
            # accounts: a draft that indexes cluster["accounts"][0] crashes here.
            missing = copy.deepcopy(base)
            missing.pop("cluster", None)
            variants.append(("cluster-missing", missing))
            empty = copy.deepcopy(base)
            empty["cluster"] = {**empty["cluster"], "accounts": []}
            variants.append(("cluster-accounts-empty", empty))
            unknown = copy.deepcopy(base)
            unknown["cluster"] = {**unknown["cluster"], "worker_type": "unknown"}
            if isinstance(unknown.get("identity"), dict):
                unknown["identity"] = {**unknown["identity"], "worker_type": "unknown"}
            variants.append(("worker-type-unknown", unknown))
        for label, row in variants:
            full_label = f"{base_id} with {label}"
            row["_subject_id"] = uuid.uuid5(_PROBE_NAMESPACE, full_label)
            row["_subject_type"] = base.get("_subject_type") or resource_type or "identity"
            probes[full_label] = row
    return probes


def _evaluate(runtime: PolicyRuntime, compiled: CompiledPolicy, rows: list[dict[str, Any]]) -> str | None:
    """Run policy() and evidence() over ``rows`` under ``runtime``; the error, if any."""
    try:
        # With ``rows`` given, evaluate_all never touches the session.
        runtime.evaluate_all(compiled, None, _NO_ORG, rows=rows)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 -- policy code can raise anything; that is what is being probed
        return f"{type(exc).__name__}: {exc}"
    return None


def _first_failure(runtime: PolicyRuntime, compiled: CompiledPolicy, probes: dict[str, dict[str, Any]]) -> str | None:
    rows = list(probes.values())
    error = _evaluate(runtime, compiled, rows)
    if error is None:
        return None
    labels = {str(row["_subject_id"]): label for label, row in probes.items()}
    for subject_id, label in labels.items():
        if subject_id in error:
            return error.replace(subject_id, repr(label))
    if isinstance(runtime, RestrictedPythonRuntime):
        # In-process errors do not name the row: find the first that fails (cheap, no subprocess).
        for label, row in probes.items():
            row_error = _evaluate(runtime, compiled, [row])
            if row_error is not None:
                return f"on probe row {label!r}: {row_error}"
    return error


def probe_policy(
    source_text: str,
    fixtures: dict[str, Any],
    *,
    runtime: PolicyRuntime | None = None,
) -> dict[str, Any] | None:
    """``{passed, probed, errors}`` for ``source_text`` over probe rows built
    from ``fixtures``, or None when the source does not compile or there is
    nothing to probe."""
    try:
        compiled = compile_and_validate(source_text)
    except PolicyCompileError:
        return None
    probes = probe_rows(expand_relative_timestamps(fixtures.get("rows") or []), compiled.contract.resource_type)
    if not probes:
        return None
    failure = _first_failure(runtime if runtime is not None else get_default_runtime(), compiled, probes)
    return {"passed": failure is None, "probed": len(probes), "errors": [failure] if failure else []}
