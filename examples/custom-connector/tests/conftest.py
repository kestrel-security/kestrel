# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Makes the scaffold connector importable when discovered from the repo root.

`examples/custom-connector` is deliberately *not* a uv workspace member -- it is
the output of `kestrel connector create`, checked in so the scaffold itself is
exercised. That means its package is not installed into the workspace venv, so
its tests have to put its `src/` on the path themselves.

Doing it here rather than requiring `PYTHONPATH=examples/custom-connector/src`
on the command line is what lets `uv run pytest` collect this directory along
with everything else, now that `examples/` is no longer excluded from
discovery.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
