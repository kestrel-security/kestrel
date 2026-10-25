// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { MfaSettings } from "@/components/mfa/mfa-settings";
import { ChangePasswordForm } from "@/components/settings/change-password-form";
import { SettingsSection } from "@/components/settings/settings-section";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { MfaStatus, Operator } from "@/lib/types";

export default async function AccountSettingsPage() {
  const [operator, mfa] = await Promise.all([
    api.get<Operator>("/auth/me"),
    api.get<MfaStatus>("/auth/mfa"),
  ]);

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Account"
        description={
          <>
            Signed in as <span className="font-medium text-foreground">{operator.email}</span>
            {operator.display_name ? ` (${operator.display_name})` : ""}.
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Change password</CardTitle>
          <CardDescription>
            If an administrator invited you with a temporary password, replace it here. Changing
            your password signs out every other session you have open, on any device; this one
            stays signed in. API tokens keep working.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ChangePasswordForm email={operator.email} />
        </CardContent>
      </Card>

      <Card id="two-factor">
        <CardHeader>
          <CardTitle>Two-factor authentication</CardTitle>
          <CardDescription>
            After your password, sign-in asks for a code from an authenticator app on your phone,
            so a leaked password alone can&apos;t open your account. API tokens are unaffected.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <MfaSettings status={mfa} email={operator.email} />
        </CardContent>
      </Card>
    </div>
  );
}
