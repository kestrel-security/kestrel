// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound } from "next/navigation";

import { OperatorInviteForm } from "@/components/settings/operator-invite-form";
import {
  OperatorActiveButton,
  OperatorResetMfaButton,
  OperatorResetPasswordButton,
  OperatorRoleSelect,
  RequireMfaToggle,
} from "@/components/settings/operator-row-actions";
import { SettingsSection } from "@/components/settings/settings-section";
import { Badge, StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api } from "@/lib/api";
import type { Operator, OrgSecurity } from "@/lib/types";

export default async function OperatorsSettingsPage() {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const [operators, security] = await Promise.all([
    api.get<Operator[]>("/operators"),
    api.get<OrgSecurity>("/org/security"),
  ]);

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Operators"
        description="Manage who can log into this Kestrel deployment and their role."
      />

      <Card>
        <CardHeader>
          <CardTitle>Sign-in security</CardTitle>
          <CardDescription>
            Operators turn on two-factor authentication at Settings → Account. Requiring it applies
            at each operator&apos;s next password sign-in. API tokens are unaffected.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RequireMfaToggle security={security} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Team</CardTitle>
          <CardDescription>
            Role changes take effect on the next request. You cannot change or deactivate your own
            account.
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/40 hover:bg-muted/40">
                <TableHead>Operator</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>MFA</TableHead>
                <TableHead>Last login</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {operators.map((op) => {
                const isSelf = op.id === me.id;
                return (
                  <TableRow key={op.id}>
                    <TableCell>
                      <div className="font-medium">{op.display_name ?? op.email}</div>
                      {op.display_name ? (
                        <div className="text-xs text-muted-foreground">{op.email}</div>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <OperatorRoleSelect operatorId={op.id} role={op.role} disabled={isSelf} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={op.is_active ? "active" : "deactivated"} />
                    </TableCell>
                    <TableCell>
                      {op.mfa_enabled ? <Badge>On</Badge> : <Badge variant="outline">Off</Badge>}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <LocalTime value={op.last_login_at} fallback="never" />
                    </TableCell>
                    <TableCell>
                      {isSelf ? (
                        <Link href="/settings/account" className="text-xs text-primary hover:underline">
                          Change your password
                        </Link>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          <OperatorResetPasswordButton operatorId={op.id} email={op.email} />
                          {op.mfa_enabled ? (
                            <OperatorResetMfaButton operatorId={op.id} email={op.email} />
                          ) : null}
                          <OperatorActiveButton
                            operatorId={op.id}
                            isActive={op.is_active}
                            email={op.email}
                          />
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Invite an operator</CardTitle>
          <CardDescription>
            Creates an account with a temporary password. Share credentials out of band.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <OperatorInviteForm />
        </CardContent>
      </Card>
    </div>
  );
}
