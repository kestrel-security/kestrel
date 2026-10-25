# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel` CLI entry point (see [project.scripts] in kestrel/pyproject.toml)."""

from __future__ import annotations

import typer

from kestrel.cli import audit as audit_cli
from kestrel.cli import connector as connector_cli
from kestrel.cli import demo as demo_cli
from kestrel.cli import gitops as gitops_cli
from kestrel.cli import init as init_cli
from kestrel.cli import operator as operator_cli
from kestrel.cli import pack as pack_cli
from kestrel.cli import policy as policy_cli
from kestrel.cli import retention as retention_cli
from kestrel.cli import secrets as secrets_cli
from kestrel.cli import sync as sync_cli
from kestrel.cli import token as token_cli

app = typer.Typer(help="Kestrel: open-source security for SaaS.", no_args_is_help=True)

app.command("init")(init_cli.init)
app.command("sync")(sync_cli.sync)
app.add_typer(connector_cli.app, name="connector")
app.add_typer(policy_cli.app, name="policy")
app.add_typer(pack_cli.app, name="pack")
app.add_typer(operator_cli.app, name="operator")
app.add_typer(token_cli.app, name="token")
app.add_typer(audit_cli.app, name="audit")
app.add_typer(retention_cli.app, name="retention")
app.add_typer(secrets_cli.app, name="secrets")
app.add_typer(demo_cli.app, name="demo")
app.add_typer(gitops_cli.app, name="gitops")
# Top-level aliases for the GitOps commands: `kestrel plan|apply|export`
app.command("export")(gitops_cli.export_cmd)
app.command("plan")(gitops_cli.plan_cmd)
app.command("apply")(gitops_cli.apply_cmd)


if __name__ == "__main__":
    app()
