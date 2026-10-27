# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel policy validate <path>` / `kestrel policy test <path> --fixtures <path>`."""

from __future__ import annotations

from pathlib import Path

import typer

from kestrel.policies.authoring import parse_policy_source
from kestrel.policies.runtime import PolicyCompileError, compile_and_validate
from kestrel.policies.testing import run_fixture_test

app = typer.Typer(help="Validate and test Python policy files.")


@app.command("validate")
def validate_cmd(path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Policy module (.py).")) -> None:
    """Compile a Python policy module with RestrictedPython (no database).

    Runs the same checks as the API's Validate, including names the sandbox
    does not provide (``datetime``, a misspelled helper).
    """
    parsed = parse_policy_source(path.read_text())
    if not parsed.is_valid or parsed.compiled is None:
        for error in parsed.errors:
            typer.secho(f"✗ {error}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho(f"✓ {parsed.compiled.contract.policy_id} is valid", fg=typer.colors.GREEN)


@app.command("test")
def test_cmd(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Policy module (.py)."),
    fixtures: Path = typer.Option(..., "--fixtures", exists=True, dir_okay=False, help="Path to a fixture-test JSON file."),
) -> None:
    """Run a policy against a fixtures JSON file and diff expected matches."""
    source = path.read_text()
    try:
        compiled = compile_and_validate(source)
    except PolicyCompileError as exc:
        typer.secho(f"✗ Compile error: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    result = run_fixture_test(source, fixtures)

    if result.passed:
        typer.secho(
            f"✓ {compiled.contract.policy_id} passed ({len(result.actual_subject_ids)} match(es))",
            fg=typer.colors.GREEN,
        )
        return

    typer.secho(f"✗ {compiled.contract.policy_id} failed", fg=typer.colors.RED)
    if result.missing:
        typer.echo(f"  missing expected matches: {sorted(result.missing)}")
    if result.unexpected:
        typer.echo(f"  unexpected matches: {sorted(result.unexpected)}")
    raise typer.Exit(code=1)
