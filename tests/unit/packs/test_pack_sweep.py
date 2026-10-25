# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The pack sweep (docs/testing.md rule 3): one
parametrized test over every `packs/*/policies/*.py`, asserting it compiles
and passes its own `.fixtures.json` via `run_fixture_test_dict`.

Every path is resolved through `kestrel.policies.packs`
(`get_packs_dir` / `list_available_packs` / `load_pack_fixture`), which
honors `KESTREL_PACKS_DIR` -- never a literal `packs/<name>` string. An
older suite hardcoded `packs/core/policies` and three tests died when that
directory went away. Adding, renaming, or removing a pack changes what this
sweep collects automatically, with no test file to edit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from kestrel.policies.loader import load_policy_file
from kestrel.policies.packs import get_packs_dir, list_available_packs, load_pack_fixture
from kestrel.policies.testing import run_fixture_test_dict


def _pack_policy_files() -> list[tuple[str, Path]]:
    """(pack_name, policy_file_path) for every `.py` file under every
    catalog pack's `policies/` directory."""
    pairs: list[tuple[str, Path]] = []
    for pack in list_available_packs():
        policies_dir = pack.path / "policies"
        if not policies_dir.is_dir():
            continue
        for policy_file in sorted(policies_dir.glob("*.py")):
            if policy_file.name.startswith("_"):
                continue
            pairs.append((pack.name, policy_file))
    return pairs


def _case_id(case: tuple[str, Path]) -> str:
    pack_name, policy_file = case
    return f"{pack_name}/{policy_file.stem}"


_CASES = _pack_policy_files()


@pytest.mark.parametrize("case", _CASES, ids=[_case_id(c) for c in _CASES])
def test_pack_policy_compiles_and_passes_its_own_fixture(case: tuple[str, Path]) -> None:
    pack_name, policy_file = case

    loaded = load_policy_file(policy_file)
    assert loaded.is_valid, f"{pack_name}/{policy_file.name} failed to compile: {loaded.errors}"

    fixture = load_pack_fixture(pack_name, loaded.slug)
    assert fixture is not None, (
        f"{pack_name}/{policy_file.name}: no {loaded.slug}.fixtures.json found under "
        f"{pack_name}/policies/fixtures/ (resolved via kestrel.policies.packs)"
    )

    result = run_fixture_test_dict(loaded.source_text, fixture)

    assert result.passed, (
        f"{pack_name}/{loaded.slug}: expected {sorted(result.expected_subject_ids)}, "
        f"got {sorted(result.actual_subject_ids)} "
        f"(missing={sorted(result.missing)}, unexpected={sorted(result.unexpected)})"
    )


def test_the_sweep_actually_collected_policies_from_more_than_one_pack() -> None:
    # A guard against this file silently sweeping zero cases (e.g.
    # KESTREL_PACKS_DIR pointed somewhere empty) and reporting a false
    # "0 passed, 0 failed" green run.
    pack_names = {pack_name for pack_name, _ in _CASES}
    assert len(_CASES) > 10
    assert len(pack_names) > 1


def _packs_dir():
    return get_packs_dir()


def test_get_packs_dir_defaults_to_a_packs_directory_next_to_the_process_cwd():
    assert get_packs_dir().name == "packs"


def test_get_packs_dir_honors_the_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("KESTREL_PACKS_DIR", str(tmp_path))
    assert get_packs_dir() == tmp_path.resolve()


@pytest.mark.parametrize("pack", list_available_packs(), ids=lambda pack: pack.name)
def test_pack_manifest_lists_exactly_the_policies_the_pack_ships(pack) -> None:
    """`pack.yaml` `policies:` drives the catalog count and install preview, so
    a policy file missing from it is invisible and a stale entry is a phantom."""
    shipped = {load_policy_file(path).slug for path in sorted((pack.path / "policies").glob("*.py"))}
    assert shipped, f"{pack.name} ships no policies"
    assert set(pack.policy_slugs) == shipped
    assert len(pack.policy_slugs) == len(shipped), f"{pack.name}: duplicate entries in pack.yaml policies"


def _defined_controls() -> set[tuple[str, str]]:
    """Every (framework, control_id) any pack's catalog defines.

    The union, not per-pack: controls install shared (`org_id = null`), so a
    policy may legitimately map to a control another pack defines -- `cross-app`
    maps to the internal control GH-01, which `github-posture` owns.
    """
    defined: set[tuple[str, str]] = set()
    for pack in list_available_packs():
        controls_path = pack.path / "compliance_controls.yaml"
        if not controls_path.exists():
            continue
        catalog = yaml.safe_load(controls_path.read_text()) or {}
        for row in catalog.get("controls") or []:
            defined.add((str(row["framework"]), str(row["control_id"])))
    return defined


@pytest.mark.parametrize("pack_name", sorted({case[0] for case in _CASES}))
def test_every_claimed_compliance_control_is_defined_by_some_pack(pack_name: str) -> None:
    """A control id no catalog defines is a mapping that installs as nothing.

    `_sync_policy_control_mappings` skips a claimed control it cannot resolve,
    so a typo or a newly invented id drops the mapping silently: the policy
    still installs, just with no compliance coverage attached, and the pack
    detail page shows a framework it does not actually cover.
    """
    pack = next(p for p in list_available_packs() if p.name == pack_name)
    policies_dir = pack.path / "policies"
    if not policies_dir.exists():
        pytest.skip(f"{pack_name} ships no policies")

    claimed: set[tuple[str, str]] = set()
    for policy_file in sorted(policies_dir.glob("*.py")):
        loaded = load_policy_file(policy_file)
        compliance = loaded.compiled.contract.compliance or {}
        for framework, control_ids in compliance.items():
            for control_id in control_ids:
                claimed.add((str(framework), str(control_id)))

    undefined = sorted(claimed - _defined_controls())
    assert not undefined, f"{pack_name}: policies claim compliance controls no pack catalog defines: {undefined}"


# A policy's `REQUIRES` is how it says "do not claim you assessed me unless the
# connector collected this". `coverage.py` reports `not_assessable` when a named
# capability is missing from the connector manifest -- so an undeclared
# capability silently turns a working check into one that never reports. Okta
# and Google Workspace declared none at all, which left thirteen policies
# unassessable on a fully collecting tenant.
def _required_capabilities() -> dict[str, set[str]]:
    """policy file -> capabilities it requires."""
    out: dict[str, set[str]] = {}
    for path in sorted(_packs_dir().glob("*/policies/*.py")):
        match = re.search(r"^REQUIRES\s*=\s*\[(.*?)\]", path.read_text(), re.M | re.S)
        if not match:
            continue
        required = set(re.findall(r'"([^"]+)"', match.group(1)))
        if required:
            out[f"{path.parent.parent.name}/{path.name}"] = required
    return out


def test_every_required_capability_is_declared_by_its_connector() -> None:
    from kestrel.connectors.sdk.registry import discover_connectors
    from kestrel.policies.coverage import load_connector_capabilities

    declared = {name: load_connector_capabilities(name) for name in discover_connectors()}
    problems: list[str] = []
    for policy, required in sorted(_required_capabilities().items()):
        for capability in sorted(required):
            connector = capability.split(":", 1)[0]
            if connector not in declared:
                continue  # a capability for an application with no installed connector
            if capability not in declared[connector]:
                problems.append(
                    f"  {policy} requires '{capability}', which {connector}'s manifest does not "
                    f"declare in `provides_capabilities`. The policy will report not_assessable "
                    f"even when the connector collected the data."
                )
    assert not problems, "policies requiring undeclared capabilities\n" + "\n".join(problems)


def test_capability_requirements_were_actually_collected() -> None:
    """Guard: a regex that matched nothing would pass the check above vacuously."""
    required = _required_capabilities()
    assert len(required) > 10, f"only {len(required)} policies with REQUIRES found — the parser is not working"
