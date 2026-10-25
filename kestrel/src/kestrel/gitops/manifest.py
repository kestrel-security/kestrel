# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""YAML desired-state schema for `kestrel export` / `plan` / `apply`."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

API_VERSION = "kestrel.dev/v1"
KIND = "DesiredState"
MANIFEST_FILENAME = "kestrel.yaml"


class GitOpsError(ValueError):
    """Raised when a manifest cannot be loaded or is structurally invalid."""


@dataclass
class PackSpec:
    """Install a pack by catalog id and/or filesystem path."""

    id: str | None = None
    path: str | None = None

    def identity(self) -> str:
        return self.id or self.path or ""


@dataclass
class PolicySpec:
    """Custom policy from a `.py` file (pack policies come via PackSpec)."""

    path: str
    enabled: bool = True
    slug: str | None = None  # filled when loaded from disk


@dataclass
class SecretRef:
    """Reference only — never a plaintext secret value."""

    field: str
    ref: str


@dataclass
class ConnectorSpec:
    """Connector instance desired state. Secrets are refs only."""

    name: str
    type: str
    external_tenant_ref: str
    auth_method: str = "pat"
    sync_mode: str = "fixtures"
    schedule_cron: str | None = None
    config: dict[str, Any] = field(default_factory=dict)
    secrets: list[SecretRef] = field(default_factory=list)


@dataclass
class ExceptionSpec:
    """Policy-scoped finding exception (not per-finding)."""

    policy: str
    reason: str
    expires_at: str | None = None


@dataclass
class DesiredState:
    """Org desired state declared in a GitOps manifest."""

    packs: list[PackSpec] = field(default_factory=list)
    policies: list[PolicySpec] = field(default_factory=list)
    connectors: list[ConnectorSpec] = field(default_factory=list)
    exceptions: list[ExceptionSpec] = field(default_factory=list)
    base_dir: Path = field(default_factory=lambda: Path("."))

    def to_dict(self) -> dict[str, Any]:
        packs: list[dict[str, str]] = []
        for p in self.packs:
            pack_entry: dict[str, str] = {}
            if p.id:
                pack_entry["id"] = p.id
            if p.path:
                pack_entry["path"] = p.path
            packs.append(pack_entry)

        policies = [{"path": p.path, "enabled": p.enabled} for p in self.policies]

        connectors: list[dict[str, Any]] = []
        for c in self.connectors:
            conn_entry: dict[str, Any] = {
                "name": c.name,
                "type": c.type,
                "external_tenant_ref": c.external_tenant_ref,
                "auth_method": c.auth_method,
                "sync_mode": c.sync_mode,
                "config": c.config,
            }
            if c.schedule_cron is not None:
                conn_entry["schedule_cron"] = c.schedule_cron
            if c.secrets:
                conn_entry["secrets"] = [{"field": s.field, "ref": s.ref} for s in c.secrets]
            connectors.append(conn_entry)

        exceptions: list[dict[str, str]] = []
        for e in self.exceptions:
            exc_entry: dict[str, str] = {"policy": e.policy, "reason": e.reason}
            if e.expires_at:
                exc_entry["expires_at"] = e.expires_at
            exceptions.append(exc_entry)

        return {
            "apiVersion": API_VERSION,
            "kind": KIND,
            "packs": packs,
            "policies": policies,
            "connectors": connectors,
            "exceptions": exceptions,
        }


def resolve_manifest_path(path: Path) -> Path:
    """Accept a directory containing kestrel.yaml or a path to the YAML file."""
    path = path.expanduser().resolve()
    if path.is_dir():
        candidate = path / MANIFEST_FILENAME
        if not candidate.is_file():
            raise GitOpsError(f"No {MANIFEST_FILENAME} found in {path}")
        return candidate
    if path.is_file():
        return path
    raise GitOpsError(f"Manifest path does not exist: {path}")


def load_manifest(path: Path) -> DesiredState:
    """Load and validate a desired-state manifest from disk."""
    manifest_path = resolve_manifest_path(path)
    try:
        raw = yaml.safe_load(manifest_path.read_text())
    except yaml.YAMLError as exc:
        raise GitOpsError(f"Invalid YAML in {manifest_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise GitOpsError(f"Manifest root must be a mapping: {manifest_path}")

    api_version = raw.get("apiVersion", API_VERSION)
    if api_version != API_VERSION:
        raise GitOpsError(f"Unsupported apiVersion '{api_version}' (expected {API_VERSION})")
    kind = raw.get("kind", KIND)
    if kind != KIND:
        raise GitOpsError(f"Unsupported kind '{kind}' (expected {KIND})")

    base_dir = manifest_path.parent
    packs = [_parse_pack(item) for item in raw.get("packs") or []]
    policies = [_parse_policy(item, base_dir) for item in raw.get("policies") or []]
    connectors = [_parse_connector(item) for item in raw.get("connectors") or []]
    exceptions = [_parse_exception(item) for item in raw.get("exceptions") or []]

    _validate_unique_names(packs, policies, connectors, exceptions)

    return DesiredState(
        packs=packs,
        policies=policies,
        connectors=connectors,
        exceptions=exceptions,
        base_dir=base_dir,
    )


def write_manifest(state: DesiredState, path: Path) -> Path:
    """Write desired state to path (file or directory → kestrel.yaml)."""
    path = path.expanduser().resolve()
    if path.suffix in {".yaml", ".yml"} or path.name == MANIFEST_FILENAME:
        out = path
        out.parent.mkdir(parents=True, exist_ok=True)
    else:
        path.mkdir(parents=True, exist_ok=True)
        out = path / MANIFEST_FILENAME

    payload = state.to_dict()
    text = yaml.safe_dump(payload, default_flow_style=False, sort_keys=False)
    out.write_text(text)
    return out


def _parse_pack(item: Any) -> PackSpec:
    if not isinstance(item, dict):
        raise GitOpsError("Each packs[] entry must be a mapping with id and/or path")
    pack_id = item.get("id")
    pack_path = item.get("path")
    if not pack_id and not pack_path:
        raise GitOpsError("packs[] entry requires id and/or path")
    if pack_id is not None and not isinstance(pack_id, str):
        raise GitOpsError("packs[].id must be a string")
    if pack_path is not None and not isinstance(pack_path, str):
        raise GitOpsError("packs[].path must be a string")
    return PackSpec(id=pack_id, path=pack_path)


def _parse_policy(item: Any, base_dir: Path) -> PolicySpec:
    if not isinstance(item, dict):
        raise GitOpsError("Each policies[] entry must be a mapping with path")
    rel = item.get("path")
    if not isinstance(rel, str) or not rel.strip():
        raise GitOpsError("policies[].path is required")
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool):
        raise GitOpsError("policies[].enabled must be a boolean")

    policy_path = (base_dir / rel).resolve()
    if not policy_path.is_file():
        raise GitOpsError(f"Policy file not found: {rel} (resolved {policy_path})")

    source = policy_path.read_text()
    from kestrel.policies.runtime import PolicyCompileError, compile_and_validate

    try:
        compiled = compile_and_validate(source)
    except PolicyCompileError as exc:
        raise GitOpsError(f"Invalid Python policy in {rel}: {exc}") from exc
    if not compiled.contract.policy_id:
        raise GitOpsError(f"Policy in {rel} is missing POLICY_ID")

    return PolicySpec(path=rel, enabled=enabled, slug=compiled.contract.policy_id)


def _parse_connector(item: Any) -> ConnectorSpec:
    if not isinstance(item, dict):
        raise GitOpsError("Each connectors[] entry must be a mapping")
    name = item.get("name")
    ctype = item.get("type")
    external = item.get("external_tenant_ref")
    if not isinstance(name, str) or not name.strip():
        raise GitOpsError("connectors[].name is required")
    if not isinstance(ctype, str) or not ctype.strip():
        raise GitOpsError("connectors[].type is required")
    if not isinstance(external, str) or not external.strip():
        raise GitOpsError("connectors[].external_tenant_ref is required")

    config = item.get("config") or {}
    if not isinstance(config, dict):
        raise GitOpsError("connectors[].config must be a mapping")
    _assert_no_secret_values(config)

    secrets_raw = item.get("secrets") or []
    if not isinstance(secrets_raw, list):
        raise GitOpsError("connectors[].secrets must be a list")
    secrets: list[SecretRef] = []
    for s in secrets_raw:
        if not isinstance(s, dict):
            raise GitOpsError("connectors[].secrets[] must be mappings with field + ref")
        field_name = s.get("field")
        ref = s.get("ref")
        if "value" in s:
            raise GitOpsError("connectors[].secrets must use field/ref only — plaintext secret values are forbidden")
        if not isinstance(field_name, str) or not field_name.strip():
            raise GitOpsError("connectors[].secrets[].field is required")
        if not isinstance(ref, str) or not ref.strip():
            raise GitOpsError(
                f"connectors[].secrets[].ref is required for field '{field_name}' "
                "(e.g. env:GITHUB_TOKEN) — never embed secret values"
            )
        if ref.startswith("value:") or ref.startswith("plaintext:"):
            raise GitOpsError(f"Forbidden secret ref scheme in '{ref}' — use env: or secret:")
        secrets.append(SecretRef(field=field_name.strip(), ref=ref.strip()))

    schedule = item.get("schedule_cron")
    if schedule is not None and not isinstance(schedule, str):
        raise GitOpsError("connectors[].schedule_cron must be a string or omitted")

    auth_method = item.get("auth_method", "pat")
    sync_mode = item.get("sync_mode", "fixtures")
    if not isinstance(auth_method, str) or not isinstance(sync_mode, str):
        raise GitOpsError("connectors[].auth_method and sync_mode must be strings")

    return ConnectorSpec(
        name=name.strip(),
        type=ctype.strip(),
        external_tenant_ref=external.strip(),
        auth_method=auth_method,
        sync_mode=sync_mode,
        schedule_cron=schedule,
        config=dict(config),
        secrets=secrets,
    )


def _parse_exception(item: Any) -> ExceptionSpec:
    if not isinstance(item, dict):
        raise GitOpsError("Each exceptions[] entry must be a mapping")
    policy = item.get("policy")
    reason = item.get("reason")
    if not isinstance(policy, str) or not policy.strip():
        raise GitOpsError("exceptions[].policy is required")
    if not isinstance(reason, str) or not reason.strip():
        raise GitOpsError("exceptions[].reason is required")
    expires = item.get("expires_at")
    if expires is not None and not isinstance(expires, str):
        raise GitOpsError("exceptions[].expires_at must be an ISO-8601 string")
    return ExceptionSpec(policy=policy.strip(), reason=reason.strip(), expires_at=expires)


_SECRETISH_KEYS = frozenset(
    {
        "token",
        "pat",
        "password",
        "secret",
        "api_key",
        "apikey",
        "client_secret",
        "private_key",
        "access_token",
        "refresh_token",
    }
)


def _assert_no_secret_values(config: dict[str, Any], *, prefix: str = "config") -> None:
    """Reject obvious plaintext secret fields in connector config."""
    for key, value in config.items():
        lowered = key.lower().replace("-", "_")
        if lowered in _SECRETISH_KEYS and isinstance(value, str) and value.strip():
            raise GitOpsError(
                f"connectors[].{prefix}.{key} looks like a secret — put credentials under secrets[].ref, never in config"
            )
        if isinstance(value, dict):
            _assert_no_secret_values(value, prefix=f"{prefix}.{key}")


def _validate_unique_names(
    packs: list[PackSpec],
    policies: list[PolicySpec],
    connectors: list[ConnectorSpec],
    exceptions: list[ExceptionSpec],
) -> None:
    pack_ids = [p.identity() for p in packs]
    if len(pack_ids) != len(set(pack_ids)):
        raise GitOpsError("Duplicate packs[] entries")

    slugs = [p.slug for p in policies if p.slug]
    if len(slugs) != len(set(slugs)):
        raise GitOpsError("Duplicate policies[] slugs")

    names = [c.name for c in connectors]
    if len(names) != len(set(names)):
        raise GitOpsError("Duplicate connectors[].name values")

    exc_keys = [(e.policy, e.reason) for e in exceptions]
    if len(exc_keys) != len(set(exc_keys)):
        raise GitOpsError("Duplicate exceptions[] (policy, reason) pairs")
