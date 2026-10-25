#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/demo-preflight.sh — fail fast, with names, when the demo cannot start.
#
# `docker compose up` reports a port collision as "Bind for 0.0.0.0:3010
# failed", which says nothing about what holds the port. The usual culprit is a
# host-run API or web dev server left over from another checkout. Report the
# process so the operator can stop it, instead of letting Compose fail halfway.
set -euo pipefail

if ! command -v lsof >/dev/null 2>&1; then
  exit 0
fi

# Host ports the demo stack publishes (see docker-compose.yml). Docker itself
# listening is fine: that is the previous run of this stack.
PORTS=(3010 8010 5433 6380 9101)
blocked=0
for port in "${PORTS[@]}"; do
  while read -r cmd pid _; do
    [[ -z "${cmd:-}" ]] && continue
    case "$cmd" in
      com.docke*|docker*|Docker*) continue ;;
    esac
    cwd="$(lsof -p "$pid" -a -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)"
    echo "demo-preflight: port $port is held by $cmd (pid $pid${cwd:+, cwd $cwd}), not by Docker." >&2
    blocked=1
  done < <(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $2}' | sort -u)
done

if [[ "$blocked" -ne 0 ]]; then
  echo "demo-preflight: stop those processes (or remap the port in docker-compose.override.yml) and re-run make demo-up." >&2
  exit 1
fi
