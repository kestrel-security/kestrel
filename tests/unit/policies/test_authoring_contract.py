# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""The policy authoring contract is derived from the sandbox and stays true.

The generate prompt, ``kestrel policy contract``, the API endpoint and the
helper table in docs/policies.md all describe what a policy may use. These
tests fail when any of them drifts from what the runtime injects, or when an
idiom stops matching the pack policy it cites.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from kestrel.cli.policy import app
from kestrel.policies import authoring_contract as contract
from kestrel.policies.authoring import parse_policy_source
from kestrel.policies.packs import get_packs_dir
from kestrel.policies.runtime.helpers import POLICY_HELPERS, POLICY_TIME
from typer.testing import CliRunner

_REPO = Path(__file__).resolve().parents[3]


def test_contract_lists_every_helper_and_is_json_safe() -> None:
    data = contract.policy_authoring_contract()
    assert [entry["name"] for entry in data["helpers"]] == list(POLICY_HELPERS)
    assert all(entry["summary"] for entry in data["helpers"])
    assert data["time"]["attributes"] == sorted(n for n in vars(POLICY_TIME) if not n.startswith("_"))
    assert "sleep" not in data["time"]["attributes"]
    assert set(data["resource_schemas"]) >= {"identity", "grant", "tenant_setting", "event", "resource", "application"}
    json.dumps(data)


def test_docs_helper_table_matches_the_runtime() -> None:
    docs = (_REPO / "docs" / "policies.md").read_text()
    table = docs.split("| Helper | Returns |", 1)[1].split("\n\n", 1)[0]
    documented = re.findall(r"^\| `([A-Za-z_]+)", table, flags=re.MULTILINE)
    assert sorted(documented) == sorted(POLICY_HELPERS)


@pytest.mark.parametrize("idiom", contract.IDIOMS, ids=lambda idiom: idiom.name)
def test_each_idiom_is_used_by_the_pack_policy_it_cites(idiom: contract.Idiom) -> None:
    source = (get_packs_dir() / idiom.example).read_text()
    assert idiom.uses in source
    assert idiom.uses in idiom.snippet or idiom.uses.rstrip("(") in idiom.snippet


def test_idiom_snippets_only_use_names_the_sandbox_provides() -> None:
    for idiom in contract.IDIOMS:
        body = "\n".join("    " + line for line in idiom.snippet.splitlines())
        source = (
            'POLICY_ID = "idiom"\nSEVERITY = "low"\nRESOURCE_TYPE = "identity"\n'
            "DORMANT_DAYS = 90\nMAX_SESSION_HOURS = 12\n\n"
            "def policy(resource):\n"
            '    application = resource.get("application") or {}\n'
            '    identity = resource.get("identity") or {}\n'
            '    event = resource.get("event") or {}\n'
            "    value = {}\n"
            f"{body}\n"
            "    return True\n"
        )
        parsed = parse_policy_source(source)
        assert parsed.is_valid, (idiom.name, [str(e) for e in parsed.errors])


def test_markdown_covers_rules_helpers_idioms_and_workflow() -> None:
    markdown = contract.render_markdown()
    for name in POLICY_HELPERS:
        assert f"### `{name}" in markdown
    for idiom in contract.IDIOMS:
        assert f"### {idiom.name}" in markdown
    assert "POST /api/v1/policies/dry-run-draft" in markdown
    assert contract.RULES[0] in markdown


def test_pack_examples_are_real_policies_for_the_connector_and_type() -> None:
    examples = contract.pack_examples("okta", "identity")
    assert 1 <= len(examples) <= 2
    for source in examples:
        assert not source.startswith("#")
        assert 'RESOURCE_TYPE = "identity"' in source
        assert parse_policy_source(source).is_valid
    assert contract.pack_examples("not-a-connector", "identity") == []
    assert contract.pack_examples(None, "identity") == []


def test_generate_prompt_includes_pack_examples_for_the_connector() -> None:
    from kestrel.policies import generate

    prompt = generate._system_prompt(resource_type="identity", connector_hint="okta")
    assert "Shipped pack policies for this connector" in prompt
    assert contract.pack_examples("okta", "identity")[0] in prompt
    assert "__PACK_EXAMPLES__" not in prompt
    assert "Shipped pack policies" not in generate._system_prompt(resource_type="identity", connector_hint=None)


# -- CLI -----------------------------------------------------------------------


def test_cli_contract_prints_markdown_and_json() -> None:
    runner = CliRunner()
    markdown = runner.invoke(app, ["contract"])
    assert markdown.exit_code == 0, markdown.output
    assert markdown.output == contract.render_markdown()
    as_json = runner.invoke(app, ["contract", "--format", "json"])
    assert as_json.exit_code == 0
    assert json.loads(as_json.output)["version"] == contract.CONTRACT_VERSION
    assert runner.invoke(app, ["contract", "--format", "yaml"]).exit_code != 0


def test_cli_validate_reports_unknown_names(tmp_path: Path) -> None:
    policy = tmp_path / "draft.py"
    policy.write_text(
        'POLICY_ID = "draft"\nSEVERITY = "low"\nRESOURCE_TYPE = "identity"\n\n'
        "def policy(resource):\n    return datetime.now().year > 2000\n"
    )
    result = CliRunner().invoke(app, ["validate", str(policy)])
    assert result.exit_code == 1
    assert "Unknown name 'datetime'" in result.output

    policy.write_text(policy.read_text().replace("datetime.now().year > 2000", "now().year > 2000"))
    result = CliRunner().invoke(app, ["validate", str(policy)])
    assert result.exit_code == 0, result.output


def test_validate_reports_time_attributes_the_sandbox_lacks() -> None:
    source = 'POLICY_ID = "draft"\nSEVERITY = "low"\n\ndef policy(resource):\n    time.sleep(1)\n    return True\n'
    (error,) = parse_policy_source(source).errors
    assert error.message.startswith("time.sleep is not available in policies")
    assert error.line == 5
