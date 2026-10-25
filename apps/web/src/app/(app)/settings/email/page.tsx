// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { notFound } from "next/navigation";

import { EmailSettingsForm } from "@/components/settings/email-settings-form";
import { SendTestEmailButton } from "@/components/settings/send-test-email-button";
import { SettingsSection } from "@/components/settings/settings-section";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { emailStatus, emailStatusLabel, type EmailStatus } from "@/lib/email-settings";
import type { EmailSettings, Operator } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<EmailStatus, { className: string; dotClass: string }> = {
  org: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  environment: {
    className: "border-tone-info/25 bg-tone-info/10 text-foreground",
    dotClass: "bg-tone-info",
  },
  not_configured: {
    className: "border-border bg-muted text-foreground",
    dotClass: "bg-muted-foreground",
  },
};

function EmailStatusBadge({ settings }: { settings: EmailSettings }) {
  const style = STATUS_STYLES[emailStatus(settings)];
  return (
    <Badge className={style.className}>
      <span className={cn("size-1.5 rounded-full opacity-80", style.dotClass)} aria-hidden />
      {emailStatusLabel(settings)}
    </Badge>
  );
}

export default async function EmailSettingsPage() {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const settings = await api.get<EmailSettings>("/settings/email");

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Email"
        description="The mail server Kestrel uses for notification emails, the watched-findings digest and scheduled dashboard exports."
        actions={<EmailStatusBadge settings={settings} />}
      />

      <Card>
        <CardHeader>
          <CardTitle>Mail server (SMTP)</CardTitle>
          <CardDescription>
            Settings saved here override the server&apos;s environment configuration for this
            organization. The password is encrypted at rest and never returned after save.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EmailSettingsForm initial={settings} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Test</CardTitle>
          <CardDescription>
            Sends a short message to your own address ({me.email}) through the mail server in
            force{settings.source === "environment" ? ", currently the server environment" : ""}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SendTestEmailButton configured={settings.configured} />
        </CardContent>
      </Card>
    </div>
  );
}
