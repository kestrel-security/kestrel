// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";

import { KpiTile } from "@/components/dashboard/kpi-tile";
import {
  DashboardBarChart,
  DashboardPieChart,
} from "@/components/dashboard/widget-charts-lazy";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import type { DashboardOverview } from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const AGE_BUCKETS: { key: string; label: string }[] = [
  { key: "0_7", label: "0–7 days" },
  { key: "7_30", label: "7–30 days" },
  { key: "30_90", label: "30–90 days" },
  { key: "90_plus", label: "90+ days" },
];

/** Preset widget bodies — command-center density, semantic badges/charts. */
export function PresetWidgetBody({
  preset,
  overview,
}: {
  preset: string;
  overview: DashboardOverview;
}) {
  const { findings, connectors, policies, webhooks, first_run } = overview;
  const webhookFailed = webhooks?.failed ?? 0;
  const webhookPending = webhooks?.pending ?? 0;

  if (preset === "first_run") {
    if (!first_run || first_run.complete) {
      return <EmptyState title="Onboarding complete" hint="Checklist hides when setup is finished." />;
    }
    return (
      <ol className="space-y-2.5 text-sm">
        {first_run.steps.map((step, index) => (
          <li key={step.id} className="flex flex-wrap items-baseline gap-2">
            <span className="w-4 tabular-nums text-muted-foreground">{index + 1}.</span>
            {step.done ? (
              <span className="text-muted-foreground line-through">{step.label}</span>
            ) : (
              <Link href={step.path} className="font-medium text-primary underline-offset-2 hover:underline">
                {step.label}
              </Link>
            )}
            {!step.done ? <span className="text-xs text-muted-foreground">{step.hint}</span> : null}
          </li>
        ))}
      </ol>
    );
  }

  if (preset === "summary_metrics") {
    const syncIssues =
      (connectors?.failed ?? 0) + (connectors?.stale ?? 0) + (connectors?.never_synced ?? 0);
    return (
      <div className="grid min-h-0 flex-1 grid-cols-2 gap-2.5 lg:grid-cols-4">
        <KpiTile
          label="Open findings"
          value={findings.open_total}
          href="/findings?status=open"
          tone={findings.open_total > 0 ? "danger" : "success"}
        />
        <KpiTile
          label="Integrations healthy"
          value={`${connectors?.healthy ?? 0}/${connectors?.connector_count ?? 0}`}
          href="/connectors"
          tone="success"
        />
        <KpiTile
          label="Sync issues"
          value={syncIssues}
          href="/connectors"
          tone={syncIssues > 0 ? "warning" : "default"}
          hint={`failed ${connectors?.failed ?? 0} · stale ${connectors?.stale ?? 0}`}
        />
        <KpiTile
          label="Webhook backlog"
          value={webhookFailed + webhookPending}
          href="/settings/webhooks"
          tone={webhookFailed > 0 ? "danger" : "default"}
          hint={`failed ${webhookFailed} · pending ${webhookPending}`}
        />
      </div>
    );
  }

  if (preset === "open_by_severity") {
    const series = SEVERITY_ORDER.map((sev) => ({
      name: sev,
      value: findings.open_by_severity?.[sev] ?? 0,
    })).filter((s) => s.value > 0);
    return (
      <Link href="/findings?status=open" className="block h-full min-h-0 flex-1">
        <DashboardBarChart series={series.length ? series : SEVERITY_ORDER.map((s) => ({ name: s, value: 0 }))} />
      </Link>
    );
  }

  if (preset === "by_status") {
    const series = Object.entries(findings.by_status ?? {})
      .map(([name, value]) => ({ name, value }))
      .filter((s) => s.value > 0);
    return (
      <div className="h-full min-h-0 flex-1">
        <DashboardPieChart series={series} />
      </div>
    );
  }

  if (preset === "connector_health") {
    const series = [
      { name: "healthy", value: connectors?.healthy ?? 0 },
      { name: "failed", value: connectors?.failed ?? 0 },
      { name: "stale", value: connectors?.stale ?? 0 },
      { name: "never", value: connectors?.never_synced ?? 0 },
      { name: "running", value: connectors?.running ?? 0 },
    ].filter((s) => s.value > 0);
    return (
      <div className="h-full min-h-0 flex-1">
        <DashboardPieChart series={series} donut />
      </div>
    );
  }

  if (preset === "top_failing_policies") {
    const items = policies?.top_failing ?? [];
    if (!items.length) {
      return <EmptyState title="No open findings by policy" hint="Policies with matches appear here." />;
    }
    return (
      <ul className="divide-y divide-border/60 text-sm">
        {items.map((row) => (
          <li key={row.policy_id} className="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0">
            <div className="min-w-0">
              <Link href={`/policies/${row.policy_id}`} className="font-medium hover:underline">
                {row.title}
              </Link>
              <div className="mt-0.5 flex items-center gap-2">
                <SeverityBadge severity={row.severity} />
                <span className="truncate text-xs text-muted-foreground">{row.slug}</span>
              </div>
            </div>
            <span className="shrink-0 tabular-nums text-muted-foreground">{row.open_count}</span>
          </li>
        ))}
      </ul>
    );
  }

  if (preset === "recent_open_findings" || preset === "my_open_findings" || preset === "unassigned_open") {
    const items =
      preset === "my_open_findings"
        ? findings.mine_preview || []
        : preset === "unassigned_open"
          ? findings.unassigned_preview || []
          : findings.recent_open || [];
    if (!items.length) {
      return <EmptyState title="No findings" hint="Nothing in this queue right now." />;
    }
    return (
      <ul className="divide-y divide-border/60 text-sm">
        {items.map((item) => (
          <li key={item.id} className="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0">
            <Link href={`/findings/${item.id}`} className="min-w-0 truncate font-medium hover:underline">
              {item.title}
            </Link>
            <SeverityBadge severity={item.severity} />
          </li>
        ))}
      </ul>
    );
  }

  if (preset === "aging_open_findings") {
    const age = findings.open_by_age || {};
    return (
      <ul className="space-y-2 text-sm">
        {AGE_BUCKETS.map((b) => (
          <li key={b.key} className="flex items-center justify-between gap-3">
            <span className="text-muted-foreground">{b.label}</span>
            <Link
              href={`/findings?status=open`}
              className="tabular-nums font-medium hover:underline"
            >
              {age[b.key] ?? 0}
            </Link>
          </li>
        ))}
      </ul>
    );
  }

  return (
    <p className="text-sm text-muted-foreground">
      Unknown preset <code className="text-xs">{preset}</code>
    </p>
  );
}

export function FindingListRows({
  rows,
}: {
  rows: { id?: string; label?: string; title?: string; severity?: string; status?: string; value?: number }[];
}) {
  if (!rows.length) return <EmptyState title="No rows" hint="Adjust filters or time range." />;
  return (
    <ul className="divide-y divide-border/60 text-sm">
      {rows.map((r, i) => (
        <li key={String(r.id ?? r.label ?? i)} className="flex items-center justify-between gap-3 py-2">
          <span className="truncate">{r.title ?? r.label}</span>
          <div className="flex items-center gap-2">
            {r.severity ? <SeverityBadge severity={r.severity} /> : null}
            {r.status ? <StatusBadge status={r.status} /> : null}
            {r.value != null ? <span className="tabular-nums text-muted-foreground">{r.value}</span> : null}
          </div>
        </li>
      ))}
    </ul>
  );
}
