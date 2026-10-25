# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""GitOps manifest parsing, validation, serialisation and plan rendering (no DB)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from kestrel.gitops import DesiredState, GitOpsError, load_manifest, resolve_manifest_path, write_manifest
from kestrel.gitops.diff import PlanChange, PlanResult
from kestrel.gitops.manifest import (
    API_VERSION,
    KIND,
    MANIFEST_FILENAME,
    ConnectorSpec,
    ExceptionSpec,
    PackSpec,
    PolicySpec,
    SecretRef,
)

POLICY_SOURCE = """
POLICY_ID = "{slug}"
TITLE = "Manifest test policy"
SEVERITY = "low"
RESOURCE_TYPE = "identity"


def policy(resource):
    return False
"""


def _write(tmp_path: Path, payload: object, name: str = MANIFEST_FILENAME) -> Path:
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else yaml.safe_dump(payload))
    return path


def _policy_file(tmp_path: Path, slug: str, filename: str | None = None) -> str:
    policies = tmp_path / "policies"
    policies.mkdir(exist_ok=True)
    name = filename or f"{slug.replace('-', '_')}.py"
    (policies / name).write_text(POLICY_SOURCE.format(slug=slug))
    return f"policies/{name}"


def _connector(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {"name": "gh", "type": "github", "external_tenant_ref": "acme"}
    entry.update(overrides)
    return entry


# --------------------------------------------------------------------------- happy path


def test_load_full_manifest_from_directory(tmp_path: Path) -> None:
    rel = _policy_file(tmp_path, "gitops-unit-a")
    _write(
        tmp_path,
        {
            "apiVersion": API_VERSION,
            "kind": KIND,
            "packs": [{"id": "some-pack"}, {"path": "./local-pack"}],
            "policies": [{"path": rel, "enabled": False}],
            "connectors": [
                _connector(
                    auth_method="pat",
                    sync_mode="live",
                    schedule_cron="0 * * * *",
                    config={"org_login": "acme", "nested": {"region": "us"}},
                    secrets=[{"field": " token ", "ref": " env:GITHUB_TOKEN "}],
                )
            ],
            "exceptions": [{"policy": "gitops-unit-a", "reason": " accepted risk ", "expires_at": "2030-01-01"}],
        },
    )

    state = load_manifest(tmp_path)

    assert state.base_dir == tmp_path.resolve()
    assert [p.identity() for p in state.packs] == ["some-pack", "./local-pack"]
    assert state.policies == [PolicySpec(path=rel, enabled=False, slug="gitops-unit-a")]
    (conn,) = state.connectors
    assert conn.sync_mode == "live"
    assert conn.schedule_cron == "0 * * * *"
    assert conn.secrets == [SecretRef(field="token", ref="env:GITHUB_TOKEN")]
    assert state.exceptions == [ExceptionSpec(policy="gitops-unit-a", reason="accepted risk", expires_at="2030-01-01")]


def test_api_version_and_kind_default_when_omitted(tmp_path: Path) -> None:
    state = load_manifest(_write(tmp_path, {"packs": None, "connectors": [_connector()]}))
    assert state.packs == []
    assert state.connectors[0].auth_method == "pat"
    assert state.connectors[0].sync_mode == "fixtures"


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    rel = _policy_file(tmp_path, "gitops-unit-rt")
    state = DesiredState(
        packs=[PackSpec(id="p1", path="./p1")],
        policies=[PolicySpec(path=rel, enabled=True)],
        connectors=[
            ConnectorSpec(
                name="gh",
                type="github",
                external_tenant_ref="acme",
                schedule_cron="*/5 * * * *",
                config={"org_login": "acme"},
                secrets=[SecretRef(field="token", ref="secret:token")],
            ),
            ConnectorSpec(name="gh2", type="github", external_tenant_ref="other"),
        ],
        exceptions=[
            ExceptionSpec(policy="gitops-unit-rt", reason="r1", expires_at="2030-01-01T00:00:00+00:00"),
            ExceptionSpec(policy="gitops-unit-rt", reason="r2"),
        ],
    )

    out = write_manifest(state, tmp_path)
    assert out == (tmp_path / MANIFEST_FILENAME).resolve()

    raw = yaml.safe_load(out.read_text())
    assert raw["apiVersion"] == API_VERSION
    assert raw["kind"] == KIND
    # Optional keys are omitted, not written as null.
    assert "schedule_cron" not in raw["connectors"][1]
    assert "secrets" not in raw["connectors"][1]
    assert "expires_at" not in raw["exceptions"][1]

    loaded = load_manifest(out)
    assert loaded.to_dict() == state.to_dict()
    assert loaded.policies[0].slug == "gitops-unit-rt"


def test_write_manifest_to_explicit_yaml_file_creates_parents(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "desired.yml"
    out = write_manifest(DesiredState(), target)
    assert out == target.resolve()
    assert yaml.safe_load(out.read_text())["packs"] == []


def test_write_manifest_to_new_directory(tmp_path: Path) -> None:
    out = write_manifest(DesiredState(), tmp_path / "fresh")
    assert out.name == MANIFEST_FILENAME
    assert out.parent.is_dir()


def test_resolve_manifest_path_variants(tmp_path: Path) -> None:
    file_path = _write(tmp_path, {})
    assert resolve_manifest_path(tmp_path) == file_path.resolve()
    assert resolve_manifest_path(file_path) == file_path.resolve()

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(GitOpsError, match=r"No kestrel\.yaml found"):
        resolve_manifest_path(empty)
    with pytest.raises(GitOpsError, match="does not exist"):
        resolve_manifest_path(tmp_path / "nope.yaml")


# --------------------------------------------------------------------------- invalid manifests


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("packs: [unclosed", "Invalid YAML"),
        ("- just\n- a list\n", "root must be a mapping"),
        ({"apiVersion": "kestrel.dev/v2"}, "Unsupported apiVersion"),
        ({"kind": "Other"}, "Unsupported kind"),
        ({"packs": ["string-entry"]}, "packs\\[\\] entry must be a mapping"),
        ({"packs": [{}]}, "requires id and/or path"),
        ({"packs": [{"id": 5}]}, "packs\\[\\].id must be a string"),
        ({"packs": [{"path": 5}]}, "packs\\[\\].path must be a string"),
        ({"packs": [{"id": "a"}, {"id": "a"}]}, "Duplicate packs"),
        ({"policies": ["x"]}, "policies\\[\\] entry must be a mapping"),
        ({"policies": [{"path": "  "}]}, "policies\\[\\].path is required"),
        ({"policies": [{"path": "p.py", "enabled": "yes"}]}, "enabled must be a boolean"),
        ({"policies": [{"path": "missing.py"}]}, "Policy file not found"),
        ({"connectors": ["x"]}, "connectors\\[\\] entry must be a mapping"),
        ({"connectors": [_connector(name="")]}, "name is required"),
        ({"connectors": [_connector(type=None)]}, "type is required"),
        ({"connectors": [_connector(external_tenant_ref=" ")]}, "external_tenant_ref is required"),
        ({"connectors": [_connector(config=["a"])]}, "config must be a mapping"),
        ({"connectors": [_connector(config={"token": "ghp_x"})]}, "config.token looks like a secret"),
        ({"connectors": [_connector(config={"auth": {"Client-Secret": "s"}})]}, "config.auth.Client-Secret"),
        ({"connectors": [_connector(secrets={"field": "token"})]}, "secrets must be a list"),
        ({"connectors": [_connector(secrets=["token"])]}, "must be mappings with field \\+ ref"),
        (
            {"connectors": [_connector(secrets=[{"field": "token", "ref": "env:X", "value": "x"}])]},
            "plaintext secret values are forbidden",
        ),
        ({"connectors": [_connector(secrets=[{"ref": "env:X"}])]}, "secrets\\[\\].field is required"),
        ({"connectors": [_connector(secrets=[{"field": "token"}])]}, "ref is required for field 'token'"),
        ({"connectors": [_connector(secrets=[{"field": "token", "ref": "value:abc"}])]}, "Forbidden secret ref"),
        ({"connectors": [_connector(secrets=[{"field": "token", "ref": "plaintext:abc"}])]}, "Forbidden secret ref"),
        ({"connectors": [_connector(schedule_cron=5)]}, "schedule_cron must be a string"),
        ({"connectors": [_connector(auth_method=1)]}, "auth_method and sync_mode must be strings"),
        ({"connectors": [_connector(), _connector()]}, "Duplicate connectors"),
        ({"exceptions": ["x"]}, "exceptions\\[\\] entry must be a mapping"),
        ({"exceptions": [{"reason": "r"}]}, "exceptions\\[\\].policy is required"),
        ({"exceptions": [{"policy": "p", "reason": ""}]}, "exceptions\\[\\].reason is required"),
        ({"exceptions": [{"policy": "p", "reason": "r", "expires_at": 2030}]}, "must be an ISO-8601 string"),
        (
            {"exceptions": [{"policy": "p", "reason": "r"}, {"policy": "p", "reason": "r"}]},
            "Duplicate exceptions",
        ),
    ],
)
def test_invalid_manifest_is_rejected(tmp_path: Path, payload: object, message: str) -> None:
    with pytest.raises(GitOpsError, match=message):
        load_manifest(_write(tmp_path, payload))


def test_empty_secret_valued_config_key_is_allowed(tmp_path: Path) -> None:
    state = load_manifest(_write(tmp_path, {"connectors": [_connector(config={"token": "", "password": None})]}))
    assert state.connectors[0].config == {"token": "", "password": None}


def test_policy_with_compile_error_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("POLICY_ID = 'x'\ndef policy(:\n")
    with pytest.raises(GitOpsError, match=r"Invalid Python policy in broken\.py"):
        load_manifest(_write(tmp_path, {"policies": [{"path": "broken.py"}]}))


def test_duplicate_policy_slugs_are_rejected(tmp_path: Path) -> None:
    a = _policy_file(tmp_path, "gitops-dup", filename="a.py")
    b = _policy_file(tmp_path, "gitops-dup", filename="b.py")
    with pytest.raises(GitOpsError, match="Duplicate policies"):
        load_manifest(_write(tmp_path, {"policies": [{"path": a}, {"path": b}]}))


# --------------------------------------------------------------------------- plan rendering


def test_plan_result_in_sync_rendering() -> None:
    result = PlanResult(changes=[PlanChange(kind="pack", identity="p", action="noop")])
    assert not result.has_drift
    assert result.exit_code == 0
    assert result.format_human() == "✓ Desired state matches the database (no drift)"
    assert json.loads(result.to_json())["in_sync"] is True


def test_plan_result_drift_rendering() -> None:
    result = PlanResult(
        changes=[
            PlanChange(kind="policy", identity="a", action="create", details={"path": "policies/a.py"}),
            PlanChange(kind="connector", identity="gh", action="update", details={"config": "changed"}),
            PlanChange(kind="pack", identity="p", action="noop"),
        ],
        unmanaged=[{"kind": "policy", "identity": "stray"}],
    )
    assert result.has_drift
    assert result.exit_code == 1
    text = result.format_human()
    assert "Drift detected:" in text
    assert "  + policy a (create) — path='policies/a.py'" in text
    assert "  ~ connector gh (update) — config='changed'" in text
    assert "pack p" not in text
    assert "  · policy stray" in text
    payload = json.loads(result.to_json())
    assert payload["in_sync"] is False
    assert [c["action"] for c in payload["changes"]] == ["create", "update", "noop"]


def test_plan_result_errors_count_as_drift() -> None:
    result = PlanResult(errors=["boom"])
    assert result.exit_code == 1
    text = result.format_human()
    assert "Plan errors:" in text
    assert "  ✗ boom" in text
    assert "No resource changes." in text
