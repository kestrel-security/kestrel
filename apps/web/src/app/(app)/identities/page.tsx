// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { AppMarkStack } from "@/components/brand/app-mark";
import { apiStatePage } from "@/components/api-state";
import { Badge } from "@/components/ui/badge";
import { AppPage } from "@/components/ui/app-page";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterChip } from "@/components/ui/filter-chip";
import { PageHeader } from "@/components/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ListSearchForm } from "@/components/list-filters";
import { api } from "@/lib/api";
import { relativeTime } from "@/lib/utils";
import type { Identity, Page } from "@/lib/types";

export const dynamic = "force-dynamic";

type SearchParams = {
  search?: string;
  privileged?: string;
  is_external?: string;
  mfa_enabled?: string;
  identity_type?: string;
};

/** One row per *person*: correlated accounts collapse into a single line. */
export default async function IdentitiesPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const params = await searchParams;
  const query = new URLSearchParams({ collapse: "true", limit: "50" });
  if (params.search) query.set("search", params.search);
  if (params.privileged) query.set("privileged", params.privileged);
  if (params.is_external) query.set("is_external", params.is_external);
  if (params.mfa_enabled) query.set("mfa_enabled", params.mfa_enabled);
  if (params.identity_type) query.set("identity_type", params.identity_type);

  let page: Page<Identity>;
  try {
    page = await api.get<Page<Identity>>(`/identities?${query.toString()}`);
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  const hasFilter = Boolean(
    params.search || params.privileged || params.is_external || params.mfa_enabled || params.identity_type,
  );

  function chipHref(next: Partial<SearchParams>): string {
    const merged = new URLSearchParams();
    const combined = { ...params, ...next };
    for (const [key, value] of Object.entries(combined)) {
      if (value) merged.set(key, value);
    }
    const qs = merged.toString();
    return qs ? `/identities?${qs}` : "/identities";
  }

  return (
    <AppPage>
      <PageHeader
        title="Identities"
        description="Every person and non-human account across connected applications, correlated into one row per identity. Open one to see what they can reach everywhere."
      >
        <div className="space-y-3">
          <ListSearchForm
            action="/identities"
            defaultValue={params.search}
            placeholder="Search by name or email…"
            preserve={{
              privileged: params.privileged,
              is_external: params.is_external,
              mfa_enabled: params.mfa_enabled,
              identity_type: params.identity_type,
            }}
          />
          <div className="flex flex-wrap items-center gap-2">
            <FilterChip
              label="Privileged"
              active={params.privileged === "true"}
              href={chipHref({ privileged: params.privileged === "true" ? undefined : "true" })}
            />
            <FilterChip
              label="External"
              active={params.is_external === "true"}
              href={chipHref({ is_external: params.is_external === "true" ? undefined : "true" })}
            />
            <FilterChip
              label="No MFA"
              active={params.mfa_enabled === "false"}
              href={chipHref({ mfa_enabled: params.mfa_enabled === "false" ? undefined : "false" })}
            />
            <FilterChip
              label="Service accounts"
              active={params.identity_type === "service_account"}
              href={chipHref({
                identity_type: params.identity_type === "service_account" ? undefined : "service_account",
              })}
            />
            {hasFilter && (
              <Link href="/identities" className="text-sm text-muted-foreground hover:underline">
                Clear all
              </Link>
            )}
          </div>
        </div>
      </PageHeader>

      {page.items.length === 0 ? (
        <EmptyState
          title={hasFilter ? "No identities match these filters" : "No identities yet"}
          hint={
            hasFilter
              ? "Try removing a filter, or search for a different name."
              : "Connect an application under Integrations and run a sync; identities appear as soon as the first run finishes."
          }
          action={
            hasFilter ? undefined : (
              <Link href="/connectors" className="text-sm font-medium underline">
                Go to Integrations
              </Link>
            )
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Identity</TableHead>
                <TableHead scope="col">Applications</TableHead>
                <TableHead scope="col" className="hidden md:table-cell">
                  Type
                </TableHead>
                <TableHead scope="col">Flags</TableHead>
                <TableHead scope="col" className="hidden lg:table-cell">
                  Last active
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.items.map((identity) => (
                <TableRow key={identity.id}>
                  <TableCell>
                    <Link href={`/identities/${identity.id}`} className="font-medium hover:underline">
                      {identity.display_name || identity.email || identity.id}
                    </Link>
                    {identity.email && identity.display_name && (
                      <p className="text-xs text-muted-foreground">{identity.email}</p>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1.5">
                      <AppMarkStack applicationTypes={identity.application_types ?? []} size={14} limit={5} />
                      {(identity.account_count ?? 1) > 1 && (
                        <span className="text-xs text-muted-foreground">{identity.account_count} accounts</span>
                      )}
                    </span>
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-muted-foreground">
                    {identity.identity_type === "service_account"
                      ? "Service account"
                      : identity.identity_type === "external_identity"
                        ? "External"
                        : "User"}
                  </TableCell>
                  <TableCell>
                    <span className="flex flex-wrap gap-1">
                      {identity.privileged && <Badge variant="destructive">Privileged</Badge>}
                      {identity.is_external && <Badge variant="outline">External</Badge>}
                      {identity.is_disabled && <Badge variant="outline">Disabled</Badge>}
                      {identity.mfa_enabled === false && <Badge variant="outline">No MFA</Badge>}
                    </span>
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-sm text-muted-foreground">
                    {identity.last_active_at ? (
                      <span title={identity.last_active_at}>
                        {relativeTime(identity.last_active_at)}
                        {identity.last_active_source === "profile" && " (profile)"}
                      </span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </AppPage>
  );
}
