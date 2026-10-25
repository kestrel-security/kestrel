# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Version of the running build.

`GET /healthz` and the OpenTelemetry resource report this, so an operator can
confirm that the release they checked out is the one serving. The order is:

1. ``KESTREL_VERSION``, when a build stamps it (a downstream pipeline that
   builds from a commit rather than a tag can set it to the tag or the SHA);
2. the installed ``kestrel`` package's own version, which the release process
   bumps alongside ``apps/*`` and the web app (``scripts/check-versions.sh``
   keeps them equal), and which an editable checkout also carries;
3. ``"dev"`` only when neither is available.
"""

from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version

DEV_VERSION = "dev"


def get_version() -> str:
    """Return the build version: the stamp, else the package version, else "dev"."""
    stamped = os.environ.get("KESTREL_VERSION", "").strip()
    if stamped:
        return stamped
    try:
        return version("kestrel")
    except PackageNotFoundError:
        return DEV_VERSION
