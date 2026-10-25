# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`packs/ruff.toml` declares exactly the names the policy runtime injects.

Ruff lints pack policies with those names as builtins so F821 still catches a
typo. If the runtime gains a helper the config does not list, every policy
using it fails lint; if the config lists a name the runtime dropped, lint
passes a policy that will fail to run. Either way the two drifted.
"""

from __future__ import annotations

import tomllib

from kestrel.policies.packs import get_packs_dir
from kestrel.policies.runtime.restricted import _restricted_namespace


def test_ruff_builtins_match_the_names_the_runtime_injects() -> None:
    config = tomllib.loads((get_packs_dir() / "ruff.toml").read_text())
    declared = set(config["builtins"])
    # Underscore names are RestrictedPython's guard hooks, which policies
    # cannot reference (the compiler rejects leading-underscore names).
    injected = {name for name in _restricted_namespace() if not name.startswith("_")}

    assert declared == injected
