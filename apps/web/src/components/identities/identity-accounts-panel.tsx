// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { AppMark } from "@/components/brand/app-mark";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { IdentityCluster } from "@/lib/types";
import { countOf } from "@/lib/plural";

const MATCH_LABELS: Record<string, string> = {
  email: "matched by email",
  display_name: "matched by name",
  self: "this account",
};

/**
 * The cross-app answer: one person, every account Kestrel correlated for them,
 * and the state of each. This is the panel that makes "still active in Slack
 * after Okta disabled them" visible without opening two admin consoles.
 */
export function IdentityAccountsPanel({
  cluster,
  currentIdentityId,
}: {
  cluster: IdentityCluster | null;
  currentIdentityId: string;
}) {
  const accounts = cluster?.accounts ?? [];
  if (accounts.length === 0) return null;

  const disabledCount = accounts.filter((account) => account.is_disabled).length;
  const mixed = disabledCount > 0 && disabledCount < accounts.length;

  return (
    <Card>
      <CardHeader className="flex flex-wrap items-baseline justify-between gap-2">
        <CardTitle>Accounts across applications</CardTitle>
        <span className="text-xs text-muted-foreground">
          {countOf(accounts.length, "account")}
        </span>
      </CardHeader>
      <CardContent className="space-y-3">
        {mixed && (
          <p className="rounded-md border border-tone-warning/40 bg-tone-warning/5 px-3 py-2 text-sm">
            Disabled in {disabledCount} of {accounts.length} applications. Access that outlives the disabled account
            is not covered by single sign-on.
          </p>
        )}
        <ul className="divide-y divide-border">
          {accounts.map((account) => (
            <li key={account.identity_id} className="flex flex-wrap items-center gap-3 py-2">
              <span className="flex min-w-0 flex-1 items-center gap-2">
                {account.application_type && (
                  <AppMark resolve={{ applicationType: account.application_type }} size={16} />
                )}
                <span className="min-w-0">
                  {account.identity_id === currentIdentityId ? (
                    <span className="font-medium">{account.application_display_name ?? account.application_type}</span>
                  ) : (
                    <Link href={`/identities/${account.identity_id}`} className="font-medium hover:underline">
                      {account.application_display_name ?? account.application_type}
                    </Link>
                  )}
                  <span className="block truncate text-xs text-muted-foreground">
                    {account.email ?? account.display_name ?? account.identity_id}
                  </span>
                </span>
              </span>
              <span className="flex flex-wrap items-center gap-1.5">
                {account.is_disabled ? (
                  <Badge variant="outline">Disabled</Badge>
                ) : (
                  <Badge variant="secondary">Active</Badge>
                )}
                {account.mfa_enabled === false && <Badge variant="outline">No MFA</Badge>}
                <span className="text-xs text-muted-foreground">{MATCH_LABELS[account.match_kind] ?? account.match_kind}</span>
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
