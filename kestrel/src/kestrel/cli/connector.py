# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel connector create <name>` / `kestrel connector validate <path>`."""

from __future__ import annotations

from pathlib import Path

import typer

from kestrel.connectors.discovery import load_connector_from_path
from kestrel.connectors.scaffold import scaffold_connector
from kestrel.connectors.sdk.runner import run_collection

app = typer.Typer(help="Scaffold and validate Kestrel connectors.")


@app.command("create")
def create(
    name: str,
    directory: Path = typer.Option(Path("connectors"), "--dir", help="Parent directory for the new connector."),
) -> None:
    """Scaffolds a working connector template at <directory>/<name>/,
    testable against its own fixtures with zero credentials."""
    try:
        target = scaffold_connector(name, directory)
    except FileExistsError as exc:
        typer.secho(f"✗ {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.secho(f"✓ Created connector scaffold at {target}", fg=typer.colors.GREEN)
    typer.echo("Next steps:")
    typer.echo(f"  1. Edit {target}/src/kestrel_connector_{name.replace('-', '_')}/{{client,collector,normalizer}}.py")
    typer.echo(f"  2. kestrel connector validate {target}")
    typer.echo(f"  3. uv run pytest {target}/tests")
    typer.echo(f"  4. See {target}/README.md to wire it in for real use")


@app.command("validate")
def validate(
    path: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Connector package directory (contains manifest.yaml)."
    ),
) -> None:
    """Validates a connector's manifest and runs it against its bundled
    fixtures with zero live credentials. Also checks change-coverage
    (fixtures → fixtures/changed) when the connector claims ChangeClasses.
    """
    from kestrel.changes.coverage import infer_change_classes, validate_change_coverage
    from kestrel.connectors.sdk.contract import check_entity_mapping

    manifest, connector_class, build_fixture_transport = load_connector_from_path(path)

    fixtures_dir = path / manifest.fixtures_path
    if not fixtures_dir.exists():
        typer.secho(f"✗ fixtures_path '{manifest.fixtures_path}' does not exist", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    connector = connector_class()
    result = run_collection(connector, config=manifest.example_config, transport_override=build_fixture_transport())

    typer.secho(f"✓ Manifest valid: {manifest.name} v{manifest.version}", fg=typer.colors.GREEN)
    typer.secho("✓ Collected against fixtures with zero credentials:", fg=typer.colors.GREEN)
    for object_type, count in result.object_type_counts.items():
        typer.echo(f"    {object_type}: {count}")
    typer.secho(f"✓ Normalized {len(result.normalized_objects)} objects", fg=typer.colors.GREEN)

    mapping_problems = check_entity_mapping(manifest, result.kinds_by_object_type)
    if mapping_problems:
        typer.secho("✗ Manifest entity mapping:", fg=typer.colors.RED)
        for problem in mapping_problems:
            typer.secho(f"    {problem}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    typer.secho(
        "✓ Entity mapping: every maps_to_entity matches a kind the normalizer emits",
        fg=typer.colors.GREEN,
    )

    claimed = infer_change_classes(manifest)
    if not claimed:
        typer.secho(
            "· No change_classes claimed (none declared / inferred) — skipping coverage check",
            fg=typer.colors.YELLOW,
        )
        return

    coverage = validate_change_coverage(
        connector=connector,
        manifest=manifest,
        fixtures_dir=fixtures_dir,
        build_fixture_transport=build_fixture_transport,
    )
    if not coverage.changed_fixtures_used:
        typer.secho(
            f"✗ Change coverage: claimed {sorted(coverage.claimed)} but "
            f"{fixtures_dir / 'changed'} is missing. Add fixtures/changed/ overlays "
            "that produce those ChangeClasses.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)
    if coverage.missing:
        typer.secho(
            f"✗ Change coverage: claimed {sorted(coverage.claimed)} but t0→t1 "
            f"observed {sorted(coverage.observed)}; missing {sorted(coverage.missing)}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)
    typer.secho(
        f"✓ Change coverage: fixtures → fixtures/changed produced {sorted(coverage.observed)} "
        f"(claimed {sorted(coverage.claimed)})",
        fg=typer.colors.GREEN,
    )
    if manifest.supports_events and not any(ot.maps_to_entity == "event" for ot in manifest.object_types):
        typer.secho(
            "· supports_events is true but no object_type maps to event — audit fixtures optional",
            fg=typer.colors.YELLOW,
        )
