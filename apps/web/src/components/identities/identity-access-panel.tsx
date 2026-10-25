// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { AppMark } from "@/components/brand/app-mark";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import type { IdentityOverview } from "@/lib/types";

export type GrantRow = {
  resource_name?: string | null;
  resource_type?: string | null;
  role_name?: string | null;
  role_is_privileged?: boolean | null;
  permission_level?: string | null;
  granted_via?: string | null;
  source_group_name?: string | null;
  application_type?: string | null;
  application_instance_display_name?: string | null;
};

export type OAuthRow = {
  oauth_application_name?: string | null;
  publisher?: string | null;
  application_type?: string | null;
  application_instance_display_name?: string | null;
  last_used_at?: string | null;
};

function grantLabel(grant: GrantRow): string {
  if (grant.role_name) return grant.role_name;
  if (grant.resource_name) {
    return grant.permission_level ? `${grant.resource_name} (${grant.permission_level})` : grant.resource_name;
  }
  return grant.permission_level ?? "Access";
}

export type AccessGroup = { label: string; type: string | null; grants: GrantRow[]; oauth: OAuthRow[] };

/** One section per application instance, holding its grants and OAuth consents. */
export function groupAccessByApplication(grants: GrantRow[], oauth: OAuthRow[]): AccessGroup[] {
  const byApplication = new Map<string, AccessGroup>();
  for (const grant of grants) {
    const key = grant.application_instance_display_name ?? grant.application_type ?? "Other";
    const bucket = byApplication.get(key) ?? { label: key, type: grant.application_type ?? null, grants: [], oauth: [] };
    bucket.grants.push(grant);
    byApplication.set(key, bucket);
  }
  for (const consent of oauth) {
    // Same key as the role grants above, so one application is one section.
    const key = consent.application_instance_display_name ?? consent.application_type ?? "Other";
    const bucket = byApplication.get(key) ?? { label: key, type: consent.application_type ?? null, grants: [], oauth: [] };
    bucket.oauth.push(consent);
    byApplication.set(key, bucket);
  }
  return [...byApplication.values()];
}

/** Access grouped by application: roles, resource grants, and OAuth consents. */
export function IdentityAccessPanel({ overview }: { overview: IdentityOverview }) {
  const groups = groupAccessByApplication(
    (overview.grants ?? []) as GrantRow[],
    (overview.oauth_grants ?? []) as OAuthRow[],
  );

  return (
    <Card>
      <CardHeader className="flex flex-wrap items-baseline justify-between gap-2">
        <CardTitle>Access</CardTitle>
        <span className="text-xs text-muted-foreground">
          {overview.access_preview?.total ? `${overview.access_preview.total} reachable objects` : ""}
        </span>
      </CardHeader>
      <CardContent className="space-y-4">
        {groups.length === 0 ? (
          <EmptyState
            title="No direct grants recorded"
            hint="Group-derived access still shows in Explore, where the path through the group is drawn."
            showMark={false}
            className="py-8"
          />
        ) : (
          groups.map((group) => (
            <div key={group.label} className="space-y-2">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                {group.type && <AppMark resolve={{ applicationType: group.type }} size={14} />}
                {group.label}
              </p>
              <ul className="space-y-1 text-sm">
                {group.grants.slice(0, 15).map((grant, index) => (
                  <li key={`grant-${index}`} className="flex flex-wrap items-center gap-2">
                    <span>{grantLabel(grant)}</span>
                    {grant.role_is_privileged && <Badge variant="destructive">Privileged</Badge>}
                    {grant.granted_via === "group" && grant.source_group_name && (
                      <span className="text-xs text-muted-foreground">via {grant.source_group_name}</span>
                    )}
                  </li>
                ))}
                {group.oauth.slice(0, 10).map((consent, index) => (
                  <li key={`oauth-${index}`} className="flex flex-wrap items-center gap-2">
                    <span>{consent.oauth_application_name ?? "OAuth application"}</span>
                    <Badge variant="outline">OAuth</Badge>
                  </li>
                ))}
              </ul>
              {group.grants.length > 15 && (
                <p className="text-xs text-muted-foreground">and {group.grants.length - 15} more grants</p>
              )}
            </div>
          ))
        )}
        <p className="text-xs text-muted-foreground">
          <Link href={overview.explore_path} className="underline">
            Open in Explore
          </Link>{" "}
          to see inherited and OAuth-derived paths as a graph.
        </p>
      </CardContent>
    </Card>
  );
}
