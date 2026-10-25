# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding investigation helpers for the findings detail / workbench.

These stay in the core library so the API router does not re-implement
subject lookup or status transition rules (e.g. `resolved_at`). Import from
the module that owns each concern:

- `status`: status parsing and transitions, exception records, and
  `FindingInvestigationError`.
- `subject`: `resolve_subject` -- subject label, deep-links, connector and
  provider-console context -- plus the lighter list-row label.
- `evidence`: evidence rows enriched with display labels and deep-links.
- `compliance`: policy context, compliance-control resolution, and
  control <-> finding cross-links.
- `related`: same-subject related findings and the same-policy cohort.
- `blast_radius`: open findings on graph neighbors, the neighbor subgraph,
  and the incident-handoff export.
- `activity`: the newest-first activity timeline.

The attack-path narrative lives in `kestrel.findings.attack_path`.
"""
