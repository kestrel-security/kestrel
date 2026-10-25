# User Experience Principles

Kestrel’s UI and CLI should make SaaS security operable without requiring SSPM expertise.

## Principles

1. **Plain language findings** — titles and descriptions a security engineer can explain to a teammate
2. **Show why it matters** — severity plus business/security context, not a mysterious score alone
3. **Show the evidence** — field values and links to subjects that caused the match
4. **Show affected identities and applications** — orient in subject cards + provenance, not jargon
5. **Show the remediation path** — remediation text from the policy plus guided playbook steps on finding detail
6. **Minimize SSPM-specific jargon** — prefer “who can access what” over product-internal names in primary UI
7. **Make custom integrations approachable** — `kestrel connector create` + Integrations Builder (manifest fields, secrets, test connection)
8. **Make policy creation testable** — validate/fixture-test before enablement; dry-run against live inventory without writing findings
9. **Expose connector health clearly** — last run status, errors, and sync affordances
10. **Avoid unexplained risk scores** — if scoring ships, show inputs and weights as labeled signals
11. **Preserve expert depth** — raw evidence, policy source, provenance — behind progressive disclosure
12. **Make failure states actionable** — 503 uninitialized → run `kestrel init`; sync failures → show run error
13. **AI is labeled and gated** — drafts never auto-enable policies or auto-resolve findings

## Current UI scope (implemented)

- **Dashboard** — multi-board switcher; sized chart widgets; posture-trend widget; preset + metric-DSL builder; PDF/CSV export + email schedules (DEC-023)
- **Integrations** — connector catalog, create/edit (config + encrypted secrets), schedule, test connection, sync, run history, health, delete
- **Identities** — correlated people across applications; per-person accounts, roles, access, risk factors, and findings
- **Explore** — identity-graph canvas (`@xyflow/react` + dagre): typed nodes, access-path edges, MiniMap/Controls, path highlight + inspect rail
- **Changes** — classified sync diff feed
- **Policies** — pack marketplace; tabbed policy workspace (Overview · Code & test · Findings · Evaluations · Versions) with URL-driven tabs; source-first Python workbench (Monaco) over a results drawer (fixtures/problems/test/dry-run); AI draft, evaluate, versions/fork
- **Findings** — advanced search command bar + chips, queues, two-column detail workbench (subject/evidence/path left; sticky status/tickets/remediation rail), handoff, bulk actions
- **Settings** — personal: Account (password, two-factor authentication) and Notifications; admin: Operators, Webhooks, Ticketing, Email (SMTP), AI (LLM keys), and Audit log
- **Notifications** — sidebar bell with unread count and an in-app inbox per operator

Detail pages (identity detail, integration health and runs, packs) are reached from the primary destinations rather than from the nav; Explore is a focused surface, not a full graph workbench (DEC-021).

## Interaction notes

- Prefer Server Components; client JS only when required (search bar, Monaco, edit-mode widget grid)
- Never display decrypted secrets in the UI
- Empty states must teach the next action (add integration, install pack, enable policy) — use `EmptyState` (mark + title + hint + CTA)
- Composition: shared `PageHeader`, tables for ops lists, investigation canvases for Findings detail / Explore
- Severity and health: icon + label + color (`SeverityBadge` / `StatusBadge`); never color-only
- Primary actions: solid violet buttons; brand gradient only on mark / login / empty accents
- Motion: 120–200ms transitions; honor `prefers-reduced-motion`; no continuous logo animation
- Match `brand/UI_STYLE_GUIDE.md` and `apps/web/src/components/ui/` — avoid one-off button farms and purple-glow BI aesthetics
