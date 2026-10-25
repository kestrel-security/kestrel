#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# uvx isolates its tool environment; point pip-audit at the locked workspace.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
site_packages="$(uv run --locked python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
uvx --from pip-audit==2.10.1 pip-audit --path "$site_packages" "$@"
