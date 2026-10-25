# Posture baseline control matrices

Source-of-truth mapping from authoritative baselines to Kestrel policy packs.
Each app doc lists controls, profile level, required connector data, collection
status, and the `POLICY_ID` that implements the check (when shipped).

**Honesty rules**

- CIS GitHub Benchmark v1.2.0 is the vendor baseline for GitHub.
- DISA Okta IDaaS STIG + Okta security best practices for Okta.
- Slack has no official CIS/CISA baseline — mappings use NIST CSF 1.1 and CIS Controls v8.1 only.
- CISA SCuBA covers Google Workspace — not GitHub, Okta, or Slack.
- Internal pack control IDs (`GH-xx`, `OKTA-xx`, `SLACK-xx`) use the `custom` framework, not `cisa`.

| App | Baseline doc | Pack | Against the baseline | Kestrel-only checks |
|-----|--------------|------|----------------------|---------------------|
| GitHub | [github.md](github.md) | `packs/github-posture` | 26/34 CIS controls | 20 |
| Okta | [okta.md](okta.md) | `packs/okta-posture` | 12/15 STIG-derived controls | 8 |
| Slack | [slack.md](slack.md) | `packs/slack-posture` | 11/14 (no official baseline) | 7 |
| Google Workspace | [google-workspace.md](google-workspace.md) | `packs/gws-posture` | **4/24 SCuBA controls** | 10 |

Two numbers, because they mean different things. The first counts rows carrying a
control id from a published baseline — the comparable figure. The second counts
Kestrel checks with no baseline equivalent, which are `collected` by definition
and would flatter the first if they were folded into it.

Google Workspace is the honest one to look at: it is the only application here
with an authoritative, enumerable, public baseline, and its 24-row denominator
still omits nine SCuBA service baselines that have not been mapped at all. Most
of that gap is a single uncollected surface, the Cloud Identity Policy API,
rather than dozens of missing checks.

Collection status values: `collected` · `needs-collection` · `not-collectable`

## These tables are checked, not just written

`tests/unit/packs/test_posture_baseline_matrices.py` parses every table and
reconciles it against the packs:

- no row names a `POLICY_ID` that does not exist;
- a row marked `collected` names a policy that actually ships;
- a `needs-collection` or `not-collectable` row names none, so planned work
  cannot be dressed up as coverage — it belongs in a GitHub issue;
- every shipped policy appears in its matrix, so the denominator cannot drift
  as a pack grows;
- every pack has a matrix, and the status, profile, and severity vocabularies
  are closed.

It was written because the tables had drifted both ways: two GitHub rows were
marked `collected` naming policies that did not exist, nine more named plausible
slugs for work that was never done, and twenty-six shipped policies appeared
nowhere. A coverage ratio computed from that would have been wrong in both the
numerator and the denominator.
