// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { NotificationPreferencesForm } from "@/components/settings/notification-preferences-form";
import { SettingsSection } from "@/components/settings/settings-section";
import { WatchDigestPreviewCard } from "@/components/settings/watch-digest-preview";
import { Callout } from "@/components/ui/callout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { Operator, OperatorNotificationPreferences } from "@/lib/types";

export default async function NotificationsSettingsPage() {
  const [me, prefs] = await Promise.all([
    api.get<Operator>("/auth/me"),
    api.get<OperatorNotificationPreferences>("/notification-preferences"),
  ]);

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Notifications"
        description="Choose how you are notified about findings and webhook delivery failures. These preferences apply only to you."
      />

      {prefs.email_configured ? null : (
        <Callout>
          <strong className="font-medium text-foreground">
            Email is not set up for this organization.
          </strong>{" "}
          {me.role === "admin" ? (
            <>
              No email is sent until a mail server is saved.{" "}
              <Link href="/settings/email" className="text-primary hover:underline">
                Set up email in Settings → Email
              </Link>
              .
            </>
          ) : (
            "No email is sent until an administrator sets it up in Settings → Email."
          )}{" "}
          In-app notifications work either way.
        </Callout>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Preferences</CardTitle>
          <CardDescription>
            In-app notifications appear under the bell in the sidebar. Email sends the same events
            to {prefs.email_configured ? "your address" : "your address once email is set up"},
            batched when several arrive together. Findings you watch reach you on every enabled
            channel regardless of the filters below. Organization webhooks under Settings → Webhooks
            are unaffected.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <NotificationPreferencesForm prefs={prefs} />
        </CardContent>
      </Card>

      <WatchDigestPreviewCard />
    </div>
  );
}
