// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { apiStatePage } from "@/components/api-state";
import { PolicyListFilters } from "@/components/policies/policy-list-filters";
import { PolicyListTable } from "@/components/policies/policy-list-table";
import { AppPage } from "@/components/ui/app-page";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Pagination } from "@/components/ui/pagination";
import { PageHeader } from "@/components/ui/page-header";
import { api, orFallback } from "@/lib/api";
import {
  applyPolicyFilters,
  parsePolicyFilters,
  sortPolicies,
  type PackFrameworks,
  PER_PAGE_OPTIONS,
  pageHref,
  paginate,
  perPageHref,
} from "@/lib/policy-filters";
import type { ConnectorInstanceSummary, PackSummary, PolicySummary } from "@/lib/types";
import { countOf } from "@/lib/plural";

/**
 * Local to this page on purpose: `lib/app-mark.ts` covers the same concept but is
 * consumed by Explore and Findings, and unifying them is a separate change.
 */
const APP_LABELS: Record<string, string> = {
  github: "GitHub",
  okta: "Okta",
  google_workspace: "Google Workspace",
  slack: "Slack",
  cross_app: "Cross-app",
  custom: "Custom",
};

const CONNECTOR_TO_APP: Record<string, string> = {
  github: "github",
  okta: "okta",
  google_workspace: "google_workspace",
  slack: "slack",
};

function appLabel(app: string | null | undefined): string {
  if (!app) return "Custom";
  return APP_LABELS[app] ?? app;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function AppMark({ application }: { application?: string | null }) {
  const letter = (APP_LABELS[application ?? ""] ?? application ?? "?").charAt(0).toUpperCase();
  return (
    <span
      className="flex h-8 w-8 items-center justify-center rounded-md bg-muted text-sm font-semibold text-foreground"
      aria-hidden
    >
      {letter}
    </span>
  );
}

export default async function PoliciesPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = searchParams ? await searchParams : {};
  const filters = parsePolicyFilters(params);
  const packError = first(params.pack_error);
  const packInstalled = first(params.pack_installed);

  let policies: PolicySummary[] = [];
  let packs: PackSummary[] = [];
  let connectors: ConnectorInstanceSummary[] = [];
  try {
    [policies, packs, connectors] = await Promise.all([
      api.get<PolicySummary[]>("/policies"),
      api.get<PackSummary[]>("/packs").catch(orFallback([] as PackSummary[])),
      api
        .get<ConnectorInstanceSummary[]>("/connector-instances")
        .catch(orFallback([] as ConnectorInstanceSummary[])),
    ]);
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  const packFrameworks: PackFrameworks = new Map(
    packs.map((p) => [p.name, new Set((p.frameworks ?? []).map((f) => f.toLowerCase()))]),
  );

  const rows = sortPolicies(
    applyPolicyFilters(policies, filters, packFrameworks),
    filters.sort,
  );
  const paged = paginate(rows, filters.page, filters.per);

  const connectedApps = new Set(
    connectors
      .map((c) => CONNECTOR_TO_APP[c.connector_name ?? ""] ?? null)
      .filter(Boolean) as string[],
  );
  const installable = packs.filter((p) => !p.installed);
  const recommended = installable.filter((p) =>
    p.application ? connectedApps.has(p.application) : false,
  );
  const fallbackRecommended = (recommended.length > 0 ? recommended : installable).slice(0, 3);

  return (
    <AppPage>
      <PageHeader
        title="Policies"
        eyebrow="Policy as code"
        description="Installed pack and custom Python policies — real policy(resource) functions, git-versioned and fixture-testable. Browse the marketplace to install app-specific packs mapped to CIS, NIST CSF, SOC2, and CISA where data supports it."
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href="/policies/packs">Pack marketplace</Link>
            </Button>
            <Button asChild size="sm">
              <Link href="/policies/new">New policy</Link>
            </Button>
          </>
        }
      />

      {packError ? (
        <Callout tone="error" className="mb-4">
          Could not install pack: {packError}
        </Callout>
      ) : null}
      {packInstalled ? (
        <Callout tone="success" className="mb-4">
          Installed pack <code className="rounded bg-muted px-1">{packInstalled}</code>.
        </Callout>
      ) : null}

      {policies.length === 0 && fallbackRecommended.length > 0 ? (
        <section className="mb-8">
          <p className="text-eyebrow mb-2">Recommended packs</p>
          <p className="mb-3 text-sm text-muted-foreground">
            Install a pack for a connected app to start evaluating posture policies.
          </p>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {fallbackRecommended.map((pack) => (
              <Link key={pack.name} href={`/policies/packs/${pack.name}`}>
                <Card className="h-full transition-colors duration-150 hover:border-primary/30 hover:bg-accent/40">
                  <CardHeader className="border-0 pb-2">
                    <div className="flex items-center gap-2">
                      <AppMark application={pack.application} />
                      <CardTitle>{pack.display_name || pack.name}</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <CardDescription className="line-clamp-2">
                      {pack.summary || pack.description || "No summary."}
                    </CardDescription>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {countOf(pack.policy_count, "policy", "policies")}
                    </p>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </section>
      ) : null}

      {policies.length > 0 ? (
        <PolicyListFilters
          policies={policies}
          filters={filters}
          packFrameworks={packFrameworks}
          shown={rows.length}
          appLabel={appLabel}
          rawQuery={first(params.q)}
        />
      ) : null}

      {policies.length === 0 ? (
        <EmptyState
          title="No policies installed yet"
          hint="Open the pack marketplace to install GitHub, Okta, Google Workspace, or Slack packs."
          action={
            <Button asChild size="sm">
              <Link href="/policies/packs">Browse packs</Link>
            </Button>
          }
        />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No policies match these filters"
          hint="Clear filters or adjust search."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href="/policies">Clear filters</Link>
            </Button>
          }
        />
      ) : (
        <>
          <PolicyListTable policies={paged.rows} filters={filters} appLabel={appLabel} />
          <Pagination
            page={paged.page}
            pageCount={paged.pageCount}
            per={filters.per}
            perOptions={PER_PAGE_OPTIONS}
            start={paged.start}
            end={paged.end}
            total={paged.total}
            noun="policies"
            hrefForPage={(page) => pageHref("/policies", filters, page)}
            hrefForPer={(per) => perPageHref("/policies", filters, per as (typeof PER_PAGE_OPTIONS)[number])}
            className="mt-3"
          />
        </>
      )}
    </AppPage>
  );
}
