// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound, redirect, unstable_rethrow } from "next/navigation";
import { GitFork } from "lucide-react";

import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiStatePage } from "@/components/api-state";
import { PackInstallPreviewPanel } from "@/components/policies/pack-install-preview";
import {
  PackCoveragePanel,
  PackEnableControls,
  PackProfileInstallLinks,
} from "@/components/policies/pack-coverage-panel";
import { formatActionError } from "@/lib/action-error";
import { ApiError, api, slugSegment } from "@/lib/api";
import { disablePack, enablePack, forkPackPolicy, installPack } from "@/lib/actions/policies";
import type { PackCoverage, PackDetail, PackInstallPreview } from "@/lib/types";

const FRAMEWORK_LABELS: Record<string, string> = {
  cis: "CIS",
  nist_csf: "NIST CSF",
  soc2: "SOC2",
  cisa: "CISA",
};

const APP_LABELS: Record<string, string> = {
  github: "GitHub",
  okta: "Okta",
  google_workspace: "Google Workspace",
  slack: "Slack",
  cross_app: "Cross-app",
  custom: "Custom",
};

const CATEGORY_ORDER = [
  "Identity",
  "Privileged access",
  "Tenant settings",
  "Repository",
  "OAuth / apps",
  "Activity",
  "Other",
];

export default async function PackDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ name: string }>;
  searchParams?: Promise<{ installed?: string; error?: string; preview?: string; profile?: string }>;
}) {
  const { name } = await params;
  const sp = searchParams ? await searchParams : {};
  const showPreview = sp.preview === "1";
  const profile = sp.profile ?? null;

  let detail: PackDetail;
  try {
    detail = await api.get<PackDetail>(`/packs/${slugSegment(name)}`);
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }

  let installPreview: PackInstallPreview | null = null;
  let previewError: string | null = null;
  let coverage: PackCoverage | null = null;
  try {
    coverage = await api.get<PackCoverage>(`/packs/${slugSegment(detail.name)}/coverage`);
  } catch (error) {
    unstable_rethrow(error);
    coverage = null;
  }
  if (showPreview) {
    try {
      const qs = profile ? `?profile=${encodeURIComponent(profile)}` : "";
      installPreview = await api.get<PackInstallPreview>(
        `/packs/${slugSegment(detail.name)}/install-preview${qs}`,
      );
    } catch (error) {
      unstable_rethrow(error);
      previewError = error instanceof ApiError ? formatActionError(error) : "Failed to load preview";
    }
  }

  async function installAction() {
    "use server";
    const result = await installPack(detail.name, profile);
    if (!result.ok) {
      redirect(`/policies/packs/${encodeURIComponent(detail.name)}?error=${encodeURIComponent(result.error)}`);
    }
    redirect(`/policies/packs/${encodeURIComponent(detail.name)}?installed=1`);
  }

  async function enableAction() {
    "use server";
    await enablePack(detail.name);
    redirect(`/policies/packs/${encodeURIComponent(detail.name)}?installed=1`);
  }

  async function disableAction() {
    "use server";
    await disablePack(detail.name);
    redirect(`/policies/packs/${encodeURIComponent(detail.name)}`);
  }

  async function forkAction(formData: FormData) {
    "use server";
    const policyId = String(formData.get("policy_id") ?? "");
    if (!policyId) {
      redirect(`/policies/packs/${encodeURIComponent(detail.name)}?error=forbidden`);
    }
    try {
      const forked = await forkPackPolicy(policyId);
      redirect(`/policies/${forked.id}`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) {
        redirect(`/policies/packs/${encodeURIComponent(detail.name)}?error=forbidden`);
      }
      throw error;
    }
  }

  const packHref = `/policies/packs/${encodeURIComponent(detail.name)}`;
  const displayName = detail.display_name || detail.name;
  const letter = (APP_LABELS[detail.application ?? ""] ?? displayName).charAt(0).toUpperCase();

  const byCategory = new Map<string, PackDetail["policies"]>();
  for (const policy of detail.policies) {
    const cat = policy.category || "Other";
    const list = byCategory.get(cat) ?? [];
    list.push(policy);
    byCategory.set(cat, list);
  }
  const categories = [
    ...CATEGORY_ORDER.filter((c) => byCategory.has(c)),
    ...[...byCategory.keys()].filter((c) => !CATEGORY_ORDER.includes(c)).sort(),
  ];

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <p className="text-sm text-muted-foreground">
        <Link href="/policies/packs" className="hover:underline">
          Pack marketplace
        </Link>{" "}
        / {displayName}
      </p>
      <PageHeader
        title={displayName}
        eyebrow="Policy pack"
        description={detail.summary || detail.description || "No description."}
        actions={
          !installPreview ? (
            <PackProfileInstallLinks packHref={packHref} installed={detail.installed} />
          ) : null
        }
      >
        <div className="flex flex-wrap items-center gap-3">
          <span className="flex h-12 w-12 items-center justify-center rounded-md bg-muted text-lg font-semibold">
            {letter}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-muted-foreground">v{detail.version}</span>
            <StatusBadge status={detail.installed ? "installed" : "available"} />
            {detail.application ? (
              <span className="text-sm text-muted-foreground">
                {APP_LABELS[detail.application] ?? detail.application}
              </span>
            ) : null}
          </div>
        </div>
        {(detail.frameworks ?? []).length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {(detail.frameworks ?? []).map((fw) => (
              <span
                key={fw}
                className="rounded border border-border px-2 py-0.5 text-xs text-muted-foreground"
              >
                {FRAMEWORK_LABELS[fw] ?? fw}
              </span>
            ))}
          </div>
        ) : null}
        {(detail.vendor_baselines ?? []).length > 0 ? (
          <p className="text-xs text-muted-foreground">
            Baselines: {(detail.vendor_baselines ?? []).join(", ")}
          </p>
        ) : null}
        {sp.installed ? (
          <p className="text-sm text-muted-foreground">Pack installed (or re-installed) successfully.</p>
        ) : null}
        {sp.error === "forbidden" ? (
          <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-700 dark:text-red-300">
            You don&apos;t have permission to do that — this action requires the Analyst role or higher.
          </p>
        ) : null}
        {sp.error && sp.error !== "forbidden" ? (
          <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-700 dark:text-red-300">
            Could not install pack: {sp.error}
          </p>
        ) : null}
      </PageHeader>

      {coverage ? <PackCoveragePanel coverage={coverage} /> : null}

      <PackEnableControls
        packName={detail.name}
        installed={detail.installed}
        enableAction={enableAction}
        disableAction={disableAction}
      />

      {showPreview && previewError ? (
        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-700 dark:text-red-300">
          Could not load install preview: {previewError}
        </p>
      ) : null}

      {installPreview ? (
        <PackInstallPreviewPanel
          preview={installPreview}
          cancelHref={packHref}
          confirmAction={installAction}
        />
      ) : null}

      {categories.map((category) => (
        <Card key={category}>
          <CardHeader>
            <CardTitle>
              {category} ({(byCategory.get(category) ?? []).length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(byCategory.get(category) ?? []).map((p) => (
                  <TableRow key={p.slug} className="align-top">
                    <TableCell>
                      {p.policy_path ? (
                        <Link href={p.policy_path} className="font-medium hover:underline">
                          {p.title || p.slug}
                        </Link>
                      ) : (
                        <span className="font-medium">{p.title || p.slug}</span>
                      )}
                      <p className="mt-0.5 font-mono text-xs text-muted-foreground">{p.slug}</p>
                      {p.description ? (
                        <p className="mt-0.5 text-xs text-muted-foreground">{p.description}</p>
                      ) : null}
                      {!p.present ? (
                        <p className="mt-0.5 text-xs text-amber-800 dark:text-amber-300">
                          Missing .py file on disk
                        </p>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      {p.severity ? <SeverityBadge severity={p.severity} /> : "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {p.installed ? "installed" : "catalog"}
                    </TableCell>
                    <TableCell>
                      {p.installed && p.policy_id ? (
                        <form action={forkAction}>
                          <input type="hidden" name="policy_id" value={p.policy_id} />
                          <button
                            type="submit"
                            className="inline-flex items-center gap-1 text-sm text-primary underline-offset-2 hover:underline"
                          >
                            <GitFork className="size-3.5" aria-hidden />
                            Fork to custom
                          </button>
                        </form>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
