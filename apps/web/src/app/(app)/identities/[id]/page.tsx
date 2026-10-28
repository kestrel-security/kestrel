// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound } from "next/navigation";

import { AppMark } from "@/components/brand/app-mark";
import { IdentityAccountsPanel } from "@/components/identities/identity-accounts-panel";
import { IdentityAccessPanel } from "@/components/identities/identity-access-panel";
import { apiStatePage } from "@/components/api-state";
import { Badge, SeverityBadge } from "@/components/ui/badge";
import { WORKER_TYPE_LABELS, describeWorkerTypeSource, workerTypeBadge } from "@/lib/worker-type";
import { AppPage } from "@/components/ui/app-page";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { ApiError, api, segment } from "@/lib/api";
import { relativeTime } from "@/lib/utils";
import type { IdentityOverview } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function IdentityDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  let overview: IdentityOverview;
  try {
    overview = await api.get<IdentityOverview>(`/identities/${segment(id)}/overview`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  const { identity, application, cluster, groups, findings, timeline } = overview;
  const title = cluster?.display_name || identity.display_name || identity.email || "Identity";
  const openFindings = findings?.open_count ?? 0;

  return (
    <AppPage>
      <PageHeader
        eyebrow="Identities"
        title={title}
        description={identity.email ?? undefined}
        status={
          <span className="flex flex-wrap items-center gap-1.5">
            {identity.privileged && <Badge variant="destructive">Privileged</Badge>}
            {workerTypeBadge(identity.worker_type) && (
              <Badge variant={workerTypeBadge(identity.worker_type)!}>
                {WORKER_TYPE_LABELS[identity.worker_type as keyof typeof WORKER_TYPE_LABELS]}
              </Badge>
            )}
            {identity.is_external && <Badge variant="outline">External</Badge>}
            {identity.is_disabled && <Badge variant="outline">Disabled</Badge>}
            {identity.mfa_enabled === false && <Badge variant="outline">No MFA</Badge>}
          </span>
        }
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link href={`/findings?subject_type=identity&subject_id=${identity.id}`}>
                Findings{openFindings ? ` (${openFindings})` : ""}
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link href={overview.explore_path}>Open in Explore</Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,22rem)]">
        <div className="space-y-6">
          <IdentityAccountsPanel cluster={cluster} currentIdentityId={identity.id} />
          <IdentityAccessPanel overview={overview} />
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader className="text-eyebrow">Account</CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Application</span>
                <span className="flex items-center gap-1.5">
                  {application.application_type && (
                    <AppMark resolve={{ applicationType: application.application_type }} size={14} />
                  )}
                  {application.application_instance_display_name ?? application.application_type ?? "—"}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Type</span>
                <span>
                  {identity.identity_type === "service_account"
                    ? "Service account"
                    : identity.identity_type === "external_identity"
                      ? "External identity"
                      : "User"}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Worker type</span>
                <span title={describeWorkerTypeSource(identity.worker_type_source)}>
                  {WORKER_TYPE_LABELS[(identity.worker_type ?? "unknown") as keyof typeof WORKER_TYPE_LABELS] ??
                    "Unknown"}
                  {identity.worker_type_source ? (
                    <span className="text-muted-foreground"> · {describeWorkerTypeSource(identity.worker_type_source)}</span>
                  ) : null}
                </span>
              </div>
              {(identity.department || identity.title) && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">Role</span>
                  <span>{[identity.title, identity.department].filter(Boolean).join(" · ")}</span>
                </div>
              )}
              {identity.manager_email && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">Manager</span>
                  <span>{identity.manager_email}</span>
                </div>
              )}
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">MFA</span>
                <span>
                  {identity.mfa_enabled === null || identity.mfa_enabled === undefined
                    ? "Unknown"
                    : identity.mfa_enabled
                      ? "Enrolled"
                      : "Not enrolled"}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Last active</span>
                <span title={identity.last_active_at ?? undefined}>
                  {identity.last_active_at ? relativeTime(identity.last_active_at) : "—"}
                </span>
              </div>
              {identity.last_active_source === "profile" && (
                <p className="text-xs text-muted-foreground">
                  This provider exposes no sign-in time; the value above is when the profile last changed, which is
                  not activity.
                </p>
              )}
            </CardContent>
          </Card>

          {groups.length > 0 && (
            <Card>
              <CardHeader className="text-eyebrow">Groups ({groups.length})</CardHeader>
              <CardContent>
                <ul className="space-y-1 text-sm">
                  {groups.slice(0, 12).map((group) => (
                    <li key={`${group.id}-${group.identity_id}`} className="truncate" title={group.description ?? undefined}>
                      {group.name}
                    </li>
                  ))}
                </ul>
                {groups.length > 12 && (
                  <p className="mt-2 text-xs text-muted-foreground">and {groups.length - 12} more</p>
                )}
              </CardContent>
            </Card>
          )}

          {findings?.items && findings.items.length > 0 && (
            <Card>
              <CardHeader className="text-eyebrow">Open findings</CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm">
                  {findings.items.slice(0, 8).map((finding) => (
                    <li key={finding.id} className="flex items-start gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <Link href={`/findings/${finding.id}`} className="min-w-0 flex-1 hover:underline">
                        {finding.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="text-eyebrow">Recent activity</CardHeader>
            <CardContent>
              {timeline.length === 0 ? (
                <EmptyState title="Nothing recorded yet" showMark={false} className="py-6" />
              ) : (
                <ul className="space-y-2 text-sm">
                  {timeline.slice(0, 10).map((item, index) => (
                    <li key={index} className="flex flex-col">
                      <span>{item.summary ?? item.kind ?? "Event"}</span>
                      {item.at && (
                        <span className="text-xs text-muted-foreground" title={item.at}>
                          {relativeTime(item.at)}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </AppPage>
  );
}
