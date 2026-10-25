// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { Suspense } from "react";
import { notFound } from "next/navigation";
import { GitFork, Play } from "lucide-react";

import {
  activateVersionAction,
  evaluatePolicyAction,
  forkPolicyAction,
  setPolicyEnabledAction,
} from "./actions";
import { DeletePolicyButton } from "@/components/policies/delete-policy-dialog";
import { PolicyDetailHeader } from "@/components/policies/policy-detail-header";
import { PolicyCodeTab } from "@/components/policies/tabs/policy-code-tab";
import { PolicyEvaluationsTab } from "@/components/policies/tabs/policy-evaluations-tab";
import { PolicyFindingsTab } from "@/components/policies/tabs/policy-findings-tab";
import { PolicyOverviewTab } from "@/components/policies/tabs/policy-overview-tab";
import { PolicyTabSkeleton } from "@/components/policies/tabs/policy-tab-skeleton";
import { PolicyVersionsTab } from "@/components/policies/tabs/policy-versions-tab";
import { apiStatePage } from "@/components/api-state";
import { AppPage } from "@/components/ui/app-page";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { ApiError, api, segment } from "@/lib/api";
import { parsePolicyTab } from "@/lib/policy-tabs";
import type { PolicyDetail } from "@/lib/types";
import { countOf } from "@/lib/plural";

export default async function PolicyDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{
    tab?: string;
    error?: string;
    evaluated?: string;
    matches?: string;
    status?: string;
  }>;
}) {
  const { id } = await params;
  const sp = await searchParams;
  const tab = parsePolicyTab(sp.tab);

  // Only the policy itself is fetched up front; each tab loads its own data, so
  // a page view costs two round-trips instead of the five it used to.
  let policy: PolicyDetail;
  try {
    policy = await api.get<PolicyDetail>(`/policies/${segment(id)}`);
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }

  const evaluateBound = evaluatePolicyAction.bind(null, id, tab);
  const forkBound = forkPolicyAction.bind(null, id, tab);
  const toggleEnabledBound = setPolicyEnabledAction.bind(null, id, tab, !policy.is_enabled);
  const activateBound = activateVersionAction.bind(null, id);

  const actions = (
    <>
      {policy.source === "pack" ? (
        <form action={forkBound}>
          <Button type="submit" variant="outline" size="sm">
            <GitFork aria-hidden />
            Fork to custom
          </Button>
        </form>
      ) : null}
      <form action={evaluateBound}>
        <Button type="submit" size="sm">
          <Play aria-hidden />
          Evaluate now
        </Button>
      </form>
      {/* One toggle rather than an Enable and a Disable button with one always
          greyed out — the disabled twin carried no information. */}
      <form action={toggleEnabledBound}>
        <Button type="submit" variant="outline" size="sm">
          {policy.is_enabled ? "Disable" : "Enable"}
        </Button>
      </form>
      {/* System policies are product-owned: disable is as far as it goes. */}
      {policy.source !== "system" ? (
        <DeletePolicyButton
          target={{
            policyId: id,
            title: policy.title,
            source: policy.source,
            packName: policy.pack_name,
            openFindingCount: policy.open_finding_count,
          }}
        />
      ) : null}
    </>
  );

  return (
    <AppPage className="space-y-6">
      {sp.error === "forbidden" ? (
        <Callout tone="error">
          You don&apos;t have permission to do that — this action requires the Analyst role or
          higher.
        </Callout>
      ) : null}

      {sp.evaluated === "1" ? (
        <Callout tone={sp.status === "error" ? "warning" : "success"}>
          Evaluation {sp.status === "error" ? "finished with an error" : "completed"}
          {sp.matches != null ? ` — ${countOf(Number(sp.matches), "match", "matches")}` : ""}.
          Findings were reconciled; dry-run in the editor stays non-mutating.
        </Callout>
      ) : null}

      <PolicyDetailHeader policy={policy} policyId={id} activeTab={tab} actions={actions} />

      {/* Keyed so the fallback actually shows when switching tabs, and so the
          header above stays painted rather than blanking with the body. */}
      <Suspense key={tab} fallback={<PolicyTabSkeleton tab={tab} />}>
        {tab === "overview" ? <PolicyOverviewTab policy={policy} policyId={id} /> : null}
        {tab === "code" ? <PolicyCodeTab policy={policy} policyId={id} /> : null}
        {tab === "findings" ? <PolicyFindingsTab policyId={id} /> : null}
        {tab === "evaluations" ? <PolicyEvaluationsTab policyId={id} /> : null}
        {tab === "versions" ? (
          <PolicyVersionsTab policyId={id} activateAction={activateBound} />
        ) : null}
      </Suspense>
    </AppPage>
  );
}
