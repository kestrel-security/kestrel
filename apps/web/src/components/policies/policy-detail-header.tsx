// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import Link from "next/link";

import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { TabNav } from "@/components/ui/tab-nav";
import {
  POLICY_TABS,
  POLICY_TAB_LABELS,
  policyTabHref,
  type PolicyTab,
} from "@/lib/policy-tabs";
import type { PolicyDetail } from "@/lib/types";

function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "never evaluated";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "never evaluated";
  const seconds = Math.round((Date.now() - then.getTime()) / 1000);
  if (seconds < 60) return "evaluated just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `evaluated ${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `evaluated ${hours}h ago`;
  const days = Math.round(hours / 24);
  return `evaluated ${days}d ago`;
}

/**
 * Identity, actions, and section tabs for the policy workspace.
 *
 * Modeled on `components/findings/finding-detail-header.tsx` — the revamp's
 * detail-header precedent — because `PageHeader` alone can't carry a breadcrumb,
 * a tab strip, and an action cluster without the pieces fighting each other.
 *
 * Presentational only: the page owns the server actions and passes them in as
 * `actions`, so this stays a plain Server Component.
 */
export function PolicyDetailHeader({
  policy,
  policyId,
  activeTab,
  actions,
}: {
  policy: PolicyDetail;
  policyId: string;
  activeTab: PolicyTab;
  actions: ReactNode;
}) {
  const meta = [
    policy.source === "pack" && policy.pack_name ? `pack · ${policy.pack_name}` : policy.source,
    policy.version != null ? `v${policy.version}` : null,
    policy.resource_type,
    formatWhen(policy.last_evaluated_at),
  ].filter(Boolean) as string[];

  return (
    <div className="rounded-lg border border-border bg-card px-4 py-4">
      <p className="mb-2 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Link href="/policies" className="hover:text-foreground hover:underline">
          Policies
        </Link>
        <span aria-hidden>/</span>
        <span className="truncate font-mono text-foreground/80">{policy.slug}</span>
      </p>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">{policy.title}</h1>
            {policy.severity ? <SeverityBadge severity={policy.severity} /> : null}
            {policy.is_enabled === true ? <StatusBadge status="enabled" /> : null}
            {policy.is_enabled === false ? <StatusBadge status="disabled" /> : null}
          </div>
          <p className="font-mono text-xs text-muted-foreground">{meta.join(" · ")}</p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
      </div>

      <TabNav
        ariaLabel="Policy sections"
        className="mt-4 border-b-0"
        items={POLICY_TABS.map((tab) => ({
          href: policyTabHref(policyId, tab),
          label: POLICY_TAB_LABELS[tab],
          active: tab === activeTab,
          // Only Findings gets a count — it rides along on the summary for free.
          count: tab === "findings" ? policy.open_finding_count : undefined,
        }))}
      />
    </div>
  );
}
