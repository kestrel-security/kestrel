// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { ActivateVersionButton } from "@/components/policies/activate-version-button";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { LocalTime } from "@/components/ui/local-time";
import { api, orFallback, segment } from "@/lib/api";
import type { PolicyVersionsResponse } from "@/lib/types";

/**
 * Versions tab — immutable source snapshots.
 *
 * Custom policies get a rollback list; pack policies are file-owned, so only the
 * installed version is shown and activation is unavailable.
 */
export async function PolicyVersionsTab({
  policyId,
  activateAction,
}: {
  policyId: string;
  activateAction: (formData: FormData) => Promise<void>;
}) {
  const versions = await api
    .get<PolicyVersionsResponse>(`/policies/${segment(policyId)}/versions`)
    .catch(orFallback(null));

  if (!versions || versions.items.length === 0) {
    return (
      <EmptyState
        title="No versions recorded"
        hint="Versions are written when a policy is installed from a pack or published from the editor."
      />
    );
  }

  const items = versions.can_activate
    ? versions.items
    : versions.items.filter((v) => v.is_current);

  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm text-muted-foreground">
        {versions.can_activate
          ? "Immutable snapshots for this custom policy. Activating a prior version moves the current pointer (a rollback) without rewriting history."
          : "Pack policies are file-owned. The installed version below is what evaluation uses — re-install the pack to update it, or fork to custom to edit and roll back."}
      </p>

      <Card className="overflow-hidden">
        <CardContent className="p-0">
          <ul className="divide-y divide-border text-sm">
            {items.map((v) => (
              <li
                key={v.id}
                className={`flex flex-wrap items-start justify-between gap-3 px-4 py-3 ${
                  v.is_current ? "bg-elevated" : ""
                }`}
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">v{v.version}</span>
                    {v.is_current ? (
                      <StatusBadge status={versions.can_activate ? "current" : "installed"} />
                    ) : null}
                    <SeverityBadge severity={v.severity} />
                    <span className="font-mono text-xs text-muted-foreground">{v.source_hash}</span>
                    {v.created_at ? (
                      <span className="tabular-nums text-xs text-muted-foreground">
                        <LocalTime value={v.created_at} />
                      </span>
                    ) : null}
                  </div>
                  <p className="truncate font-mono text-xs text-muted-foreground">
                    {v.source_preview}
                  </p>
                </div>
                {versions.can_activate && !v.is_current ? (
                  <ActivateVersionButton
                    versionId={v.id}
                    versionLabel={`v${v.version}`}
                    action={activateAction}
                  />
                ) : null}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
