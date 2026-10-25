# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Guards the test-module identity property described in `pyproject.toml`.

Three files in this repository share the basename `test_collection_identity.py`
on purpose: `tests/unit/`, `tests/integration/` and
`examples/custom-connector/tests/`. Under `--import-mode=importlib` a test
module is named after its path relative to the repository root, which makes
that name unique -- but an `__init__.py` in a test directory renames the module
after its package root instead, and a package root short of the repository root
truncates the name until two files collide. The loser of that collision never
runs: pytest reports two passing node ids and executes one file's body twice.
That is why `examples/` used to be excluded from discovery instead of fixed.

Each copy asserts that it is the module it thinks it is, so the truncation
fails a test rather than silently swallowing one. See `pyproject.toml`.
"""

from __future__ import annotations

from pathlib import Path

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[3]


def test_module_name_is_its_path_relative_to_the_repository_root():
    expected = ".".join(_THIS_FILE.relative_to(_REPO_ROOT).with_suffix("").parts)
    assert __name__ == expected, (
        f"module imported as {__name__!r}, expected {expected!r} -- a same-basename "
        f"test module elsewhere in the tree may be shadowing this one"
    )


def test_module_file_is_this_file():
    assert Path(__file__).resolve() == _THIS_FILE


def test_the_scaffold_package_is_importable_from_the_root_test_run():
    """`examples/custom-connector` is a standalone scaffold, not a workspace
    member, so its package is not installed. The sibling `conftest.py` puts its
    `src/` on `sys.path`; without that, discovering this directory from the
    repository root would fail with ModuleNotFoundError."""
    import kestrel_connector_acme_widgets

    assert kestrel_connector_acme_widgets.__file__ is not None
