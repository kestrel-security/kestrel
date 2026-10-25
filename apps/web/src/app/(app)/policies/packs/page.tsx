// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterChip } from "@/components/ui/filter-chip";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { apiStatePage } from "@/components/api-state";
import { api } from "@/lib/api";
import { filterHref } from "@/lib/list-filters";
import type { PackSummary } from "@/lib/types";
import { countOf } from "@/lib/plural";

const APP_ORDER = [
  "github",
  "okta",
  "google_workspace",
  "slack",
  "cross_app",
  "custom",
] as const;

const APP_LABELS: Record<string, string> = {
  github: "GitHub",
  okta: "Okta",
  google_workspace: "Google Workspace",
  slack: "Slack",
  cross_app: "Cross-app",
  custom: "Custom",
};

const FRAMEWORK_LABELS: Record<string, string> = {
  cis: "CIS",
  nist_csf: "NIST CSF",
  soc2: "SOC2",
  cisa: "CISA",
};

function preserveFilters(basePath: string, current: URLSearchParams, dropKeys: string[]): string {
  const next = new URLSearchParams(current);
  for (const key of dropKeys) next.delete(key);
  const qs = next.toString();
  return qs ? `${basePath}?${qs}` : basePath;
}

function appSortIndex(application: string | null | undefined): number {
  const key = application ?? "other";
  const idx = (APP_ORDER as readonly string[]).indexOf(key);
  return idx === -1 ? APP_ORDER.length : idx;
}

function sortPacks(packs: PackSummary[]): PackSummary[] {
  return [...packs].sort((a, b) => {
    const appDiff = appSortIndex(a.application) - appSortIndex(b.application);
    if (appDiff !== 0) return appDiff;
    return (a.display_name || a.name).localeCompare(b.display_name || b.name);
  });
}

export default async function PackMarketplacePage({
  searchParams,
}: {
  searchParams?: Promise<{
    status?: string;
    application?: string;
    framework?: string;
    q?: string;
    pack_error?: string;
    pack_installed?: string;
  }>;
}) {
  const params = searchParams ? await searchParams : {};
  const status = params.status === "installed" || params.status === "available" ? params.status : undefined;
  const application = params.application?.trim() || undefined;
  const framework = params.framework?.trim() || undefined;
  const q = params.q?.trim().toLowerCase() ?? "";

  let packs: PackSummary[] = [];
  try {
    packs = await api.get<PackSummary[]>("/packs");
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  let filtered = packs;
  if (status === "installed") filtered = filtered.filter((p) => p.installed);
  if (status === "available") filtered = filtered.filter((p) => !p.installed);
  if (application) filtered = filtered.filter((p) => p.application === application);
  if (framework) {
    filtered = filtered.filter((p) =>
      (p.frameworks ?? []).some((f) => f.toLowerCase() === framework.toLowerCase()),
    );
  }
  if (q) {
    filtered = filtered.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.display_name || "").toLowerCase().includes(q) ||
        (p.summary || "").toLowerCase().includes(q) ||
        (p.description || "").toLowerCase().includes(q) ||
        (p.policy_slugs ?? []).some((s) => s.toLowerCase().includes(q)),
    );
  }

  const current = new URLSearchParams();
  if (status) current.set("status", status);
  if (application) current.set("application", application);
  if (framework) current.set("framework", framework);
  if (q) current.set("q", q);

  const sorted = sortPacks(filtered);

  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        <Link href="/policies" className="hover:underline">
          Policies
        </Link>{" "}
        / Packs
      </p>
      <PageHeader
        title="Policy pack marketplace"
        description="Install posture packs by application. Framework chips show CIS / NIST CSF / SOC2 / CISA mappings where collected data supports them — not full Foundations catalogs."
        actions={
          <Button asChild variant="outline" size="sm">
            <Link href="/policies">Installed policies</Link>
          </Button>
        }
      />

      {params.pack_error ? (
        <p className="rounded-md border border-border bg-muted/40 px-3 py-2 text-sm text-red-700">
          Could not install pack: {params.pack_error}
        </p>
      ) : null}
      {params.pack_installed ? (
        <p className="rounded-md border border-border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
          Installed pack <code className="rounded bg-muted px-1">{params.pack_installed}</code>.
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-1.5">
        {(
          [
            { id: undefined, label: "All" },
            { id: "available", label: "Available" },
            { id: "installed", label: "Installed" },
          ] as const
        ).map((chip) => (
          <FilterChip
            key={chip.label}
            href={
              chip.id
                ? filterHref("/policies/packs", current, "status", chip.id)
                : preserveFilters("/policies/packs", current, ["status"])
            }
            label={chip.label}
            active={status === chip.id || (!status && !chip.id)}
          />
        ))}
        <span className="mx-1 text-xs text-muted-foreground">·</span>
        <FilterChip
          href={preserveFilters("/policies/packs", current, ["application"])}
          label="All apps"
          active={!application}
        />
        {APP_ORDER.map((app) => (
          <FilterChip
            key={app}
            href={filterHref("/policies/packs", current, "application", app)}
            label={APP_LABELS[app]}
            active={application === app}
          />
        ))}
        <span className="mx-1 text-xs text-muted-foreground">·</span>
        <FilterChip
          href={preserveFilters("/policies/packs", current, ["framework"])}
          label="All frameworks"
          active={!framework}
        />
        {Object.entries(FRAMEWORK_LABELS).map(([id, label]) => (
          <FilterChip
            key={id}
            href={filterHref("/policies/packs", current, "framework", id)}
            label={label}
            active={framework === id}
          />
        ))}
        <form className="ml-auto flex gap-2" action="/policies/packs" method="get">
          {status ? <input type="hidden" name="status" value={status} /> : null}
          {application ? <input type="hidden" name="application" value={application} /> : null}
          {framework ? <input type="hidden" name="framework" value={framework} /> : null}
          <Input
            name="q"
            defaultValue={params.q ?? ""}
            placeholder="Search packs…"
            className="h-8 w-48"
          />
          <Button type="submit" variant="outline" size="sm">
            Search
          </Button>
        </form>
      </div>

      {sorted.length === 0 ? (
        <EmptyState
          title="No packs match"
          hint="Clear filters or add packs under the configured KESTREL_PACKS_DIR."
        />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {sorted.map((pack) => (
            <PackTile key={pack.name} pack={pack} />
          ))}
        </div>
      )}
    </div>
  );
}

function PackTile({ pack }: { pack: PackSummary }) {
  const previewHref = `/policies/packs/${encodeURIComponent(pack.name)}?preview=1`;
  const appLabel = APP_LABELS[pack.application ?? ""] ?? pack.application ?? "Other";
  const letter = (appLabel !== "Other" ? appLabel : pack.display_name ?? pack.name)
    .charAt(0)
    .toUpperCase();

  return (
    <Card className="flex h-full flex-col">
      <CardHeader className="border-0 pb-2">
        <p className="text-eyebrow mb-2">{appLabel}</p>
        <div className="flex items-start gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted text-base font-semibold">
            {letter}
          </span>
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle>
                <Link href={`/policies/packs/${pack.name}`} className="hover:underline">
                  {pack.display_name || pack.name}
                </Link>
              </CardTitle>
              <span className="font-mono text-xs text-muted-foreground">v{pack.version}</span>
              <StatusBadge status={pack.installed ? "installed" : "available"} />
            </div>
            <CardDescription className="line-clamp-2">
              {pack.summary || pack.description || "No summary."}
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1 pt-0">
        {(pack.frameworks ?? []).length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {(pack.frameworks ?? []).map((fw) => (
              <span
                key={fw}
                className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
              >
                {FRAMEWORK_LABELS[fw] ?? fw}
              </span>
            ))}
          </div>
        ) : null}
      </CardContent>
      <CardFooter className="justify-between">
        <span className="text-xs text-muted-foreground">
          {countOf(pack.policy_count, "policy", "policies")}
        </span>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href={`/policies/packs/${pack.name}`}>Details</Link>
          </Button>
          <Button asChild size="sm">
            <Link href={previewHref}>{pack.installed ? "Re-install" : "Install"}</Link>
          </Button>
        </div>
      </CardFooter>
    </Card>
  );
}
