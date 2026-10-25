// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { FindingHref, inAppFindingLink } from "@/components/findings/finding-link";
import { AppMark } from "@/components/brand/app-mark";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { resolveAppMark } from "@/lib/app-mark";
import type { FindingSubject } from "@/lib/types";

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string" || typeof value === "number") return String(value);
  return JSON.stringify(value, null, 2);
}

/** Objects and arrays render as indented JSON, which needs the full row. */
function isStructured(value: unknown): boolean {
  return value !== null && typeof value === "object";
}

export function FindingSubjectCard({ subject }: { subject: FindingSubject }) {
  const ctx = subject.context ?? {};
  const label = subject.label ?? `${subject.type} ${subject.id.slice(0, 8)}…`;
  const detailHref = inAppFindingLink(subject.detail_path);

  return (
    <Card id="subject">
      <CardHeader className="text-eyebrow">What violated the policy</CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div>
          <p className="text-eyebrow">{subject.type}</p>
          {detailHref ? (
            <FindingHref href={detailHref} className="break-words text-lg font-semibold hover:underline">
              {label}
            </FindingHref>
          ) : (
            <p className="break-words text-lg font-semibold">{label}</p>
          )}
          {subject.secondary && subject.type !== "setting" ? (
            <p className="break-words text-muted-foreground">{subject.secondary}</p>
          ) : null}
        </div>

        {subject.type === "setting" ? (
          <dl className="grid gap-2 sm:grid-cols-2">
            <div className={isStructured(ctx.setting_value) ? "min-w-0 sm:col-span-2" : "min-w-0"}>
              <dt className="text-xs text-muted-foreground">Current value</dt>
              <dd
                className={
                  isStructured(ctx.setting_value)
                    ? "max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-amber-50 px-2 py-1 font-mono text-xs text-amber-950 dark:bg-amber-950/40 dark:text-amber-100"
                    : "whitespace-pre-wrap break-all rounded-md bg-amber-50 px-2 py-1 font-mono text-amber-950 dark:bg-amber-950/40 dark:text-amber-100"
                }
              >
                {formatValue(ctx.setting_value)}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">Setting key</dt>
              <dd className="break-all font-mono text-xs">{String(ctx.setting_key ?? subject.secondary ?? "—")}</dd>
            </div>
            {ctx.setting_description ? (
              <div className="min-w-0 sm:col-span-2">
                <dt className="text-xs text-muted-foreground">Description</dt>
                <dd className="text-muted-foreground">{String(ctx.setting_description)}</dd>
              </div>
            ) : null}
          </dl>
        ) : null}

        {subject.type === "identity" ? (
          <dl className="grid gap-2 sm:grid-cols-2">
            <div>
              <dt className="text-xs text-muted-foreground">Email</dt>
              <dd className="break-all font-mono text-xs">{String(ctx.email ?? subject.secondary ?? "—")}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">MFA</dt>
              <dd
                className={
                  ctx.mfa_enabled === false
                    ? "rounded-md bg-amber-50 px-2 py-1 font-medium text-amber-950 dark:bg-amber-950/40 dark:text-amber-100"
                    : undefined
                }
              >
                {ctx.mfa_enabled === null || ctx.mfa_enabled === undefined
                  ? "unknown"
                  : ctx.mfa_enabled
                    ? "enabled"
                    : "disabled"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">External</dt>
              <dd>{ctx.is_external ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Disabled</dt>
              <dd>{ctx.is_disabled ? "yes" : "no"}</dd>
            </div>
            {subject.graph_focus_path ? (
              <div className="sm:col-span-2">
                <FindingHref href={subject.graph_focus_path} className="text-xs underline">
                  Explore access →
                </FindingHref>
              </div>
            ) : null}
          </dl>
        ) : null}

        {subject.type === "identity" && subject.cluster && subject.cluster.accounts.length > 1 ? (
          <div className="border-t border-border pt-3">
            <p className="mb-1 text-eyebrow">Same person, other applications</p>
            <ul className="space-y-1">
              {subject.cluster.accounts.map((account) => (
                <li key={account.identity_id} className="flex flex-wrap items-center gap-2">
                  <AppMark
                    mark={resolveAppMark({ applicationType: account.application_type, label: account.display_name })}
                    size={14}
                  />
                  <FindingHref href={`/identities/${account.identity_id}`} className="hover:underline">
                    {account.application_display_name ?? account.application_type ?? account.identity_id}
                  </FindingHref>
                  <span className="text-xs text-muted-foreground">
                    {account.is_disabled ? "disabled" : "active"}
                    {account.mfa_enabled === false ? " · no MFA" : ""}
                  </span>
                </li>
              ))}
            </ul>
            {subject.identity_path && (
              <p className="mt-2">
                <FindingHref href={subject.identity_path} className="text-xs underline">
                  Open identity →
                </FindingHref>
              </p>
            )}
          </div>
        ) : null}

        {subject.type === "application" ? (
          <dl className="grid gap-2 sm:grid-cols-2">
            <div>
              <dt className="text-xs text-muted-foreground">Tenant ref</dt>
              <dd className="break-all font-mono text-xs">{String(ctx.external_tenant_ref ?? subject.secondary ?? "—")}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Status</dt>
              <dd>{String(ctx.status ?? "—")}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Type</dt>
              <dd className="flex items-center gap-2">
                <AppMark
                  mark={resolveAppMark({
                    applicationType:
                      typeof ctx.application_type === "string" ? ctx.application_type : null,
                    label: subject.label,
                  })}
                  size={14}
                />
                {String(ctx.application_type ?? "—")}
              </dd>
            </div>
          </dl>
        ) : null}

        {Boolean(ctx.application_display_name || ctx.external_tenant_ref || ctx.application_type) && (
          <div className="border-t border-border pt-3">
            <p className="mb-1 text-eyebrow">Application</p>
            <p className="flex flex-wrap items-center gap-2">
              <AppMark
                mark={resolveAppMark({
                  applicationType:
                    typeof ctx.application_type === "string" ? ctx.application_type : null,
                  label:
                    typeof ctx.application_display_name === "string"
                      ? ctx.application_display_name
                      : null,
                })}
                size={16}
              />
              <span>
                {String(ctx.application_display_name ?? ctx.application_type ?? "—")}
                {ctx.external_tenant_ref ? (
                  <span className="text-muted-foreground"> · {String(ctx.external_tenant_ref)}</span>
                ) : null}
                {ctx.application_type ? (
                  <span className="text-muted-foreground"> · {String(ctx.application_type)}</span>
                ) : null}
              </span>
            </p>
          </div>
        )}

        <div className="flex flex-wrap gap-x-4 gap-y-1">
          <FindingHref href={subject.provider_console_url}>
            {subject.provider_console_label ?? "Open in provider"} →
          </FindingHref>
          <FindingHref href={subject.connector_path}>Integration →</FindingHref>
          <FindingHref
            href={
              subject.findings_list_path ??
              `/findings?subject_type=${encodeURIComponent(subject.type)}&subject_id=${subject.id}`
            }
          >
            Findings for this subject →
          </FindingHref>
        </div>
      </CardContent>
    </Card>
  );
}
