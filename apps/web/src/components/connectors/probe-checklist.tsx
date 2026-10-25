// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { CheckCircle2, CircleDashed, XCircle } from "lucide-react";

import type { ConnectorProbeResult } from "@/lib/types";

/** Human labels for the probe keys connectors report. Unknown keys fall back to the key. */
const LABELS: Record<string, string> = {
  "org.settings": "Organization settings",
  "users.list": "Users",
  "users.roles": "Admin roles",
  "groups.list": "Groups",
  "apps.list": "Applications",
  "logs.list": "System Log",
  "audit.logs": "Audit Logs",
  "admin.apps.approved.list": "App inventory (Enterprise Grid)",
  "admin.roles.listAssignments": "Org roles (Enterprise Grid)",
  "admin.teams.list": "Workspaces (Enterprise Grid)",
  "team.info": "Workspace",
  "usergroups.list": "User groups",
  "directory.users": "Directory users",
  "directory.groups": "Directory groups",
  "directory.roles": "Admin roles",
  "drive.drives": "Shared drives",
  "reports.login": "Audit reports",
  organization: "Organization",
  members: "Members",
  teams: "Teams",
  repos: "Repositories",
  audit_log: "Audit log",
};

function label(key: string): string {
  return LABELS[key] ?? key.replace(/[._]/g, " ");
}

/**
 * Renders a probe result as a permission checklist: every check the connector
 * ran, green or red, with the classified message underneath.
 */
export function ProbeChecklist({ result }: { result: ConnectorProbeResult }) {
  const entries = Object.entries(result.checked_permissions ?? {});
  const failed = entries.filter(([, ok]) => !ok).length;
  return (
    <div
      className={`space-y-2 rounded-md border p-3 text-sm ${
        result.ok ? "border-tone-success/40 bg-tone-success/5" : "border-destructive/40 bg-destructive/5"
      }`}
      role="status"
    >
      <p className="flex items-start gap-1.5 font-medium">
        {result.ok ? (
          <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-tone-success" aria-hidden />
        ) : (
          <XCircle className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden />
        )}
        <span>
          {result.ok
            ? "Connection verified"
            : failed > 0
              ? `${failed} of ${entries.length} checks failed`
              : "Connection failed"}
        </span>
      </p>
      {entries.length > 0 && (
        <ul className="grid gap-1 sm:grid-cols-2">
          {entries.map(([key, ok]) => (
            <li key={key} className="flex items-center gap-1.5">
              {ok ? (
                <CheckCircle2 className="size-3.5 shrink-0 text-tone-success" aria-hidden />
              ) : (
                <CircleDashed className="size-3.5 shrink-0 text-destructive" aria-hidden />
              )}
              <span className={ok ? "" : "text-destructive"}>{label(key)}</span>
            </li>
          ))}
        </ul>
      )}
      {result.message && <p className="text-xs text-muted-foreground">{result.message}</p>}
    </div>
  );
}
