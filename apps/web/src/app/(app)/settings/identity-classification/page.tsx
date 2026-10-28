// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { notFound } from "next/navigation";

import { IdentityClassificationForm } from "@/components/settings/identity-classification-form";
import { SettingsSection } from "@/components/settings/settings-section";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { ClassificationRules, Operator } from "@/lib/types";

export default async function IdentityClassificationSettingsPage() {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const settings = await api.get<ClassificationRules>("/settings/identity-classification");

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="Identity classification"
        description="Rules that decide whether an account belongs to an employee, a contractor, a vendor, or a guest. Connectors classify what their provider knows (Okta user type, Slack guest tiers, GitHub outside collaborators); rules cover the rest, such as a Google Workspace org unit or a vendor's email domain. Cross-application policies read the result as worker_type."
      />

      <Card>
        <CardHeader>
          <CardTitle>Rules</CardTitle>
          <CardDescription>
            Evaluated top to bottom; the first match wins and outranks the provider&apos;s own label. Bots
            stay service accounts whatever the rules say. Saving reclassifies every identity immediately,
            without a sync.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <IdentityClassificationForm initial={settings} />
        </CardContent>
      </Card>
    </div>
  );
}
