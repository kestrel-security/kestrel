// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { notFound } from "next/navigation";

import { AiSettingsForm } from "@/components/settings/ai-settings-form";
import { SettingsSection } from "@/components/settings/settings-section";
import { StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { AiSettings, Operator } from "@/lib/types";

function aiStatus(settings: AiSettings): string {
  if (!settings.configured) return "not configured";
  if (!settings.is_enabled) return "disabled";
  return "configured";
}

export default async function AiSettingsPage() {
  const me = await api.get<Operator>("/auth/me");
  if (me.role !== "admin") {
    notFound();
  }

  const settings = await api.get<AiSettings>("/settings/ai");

  return (
    <div className="space-y-6">
      <SettingsSection
        eyebrow="Settings"
        title="AI"
        description="Connect OpenAI (ChatGPT) or Anthropic (Claude) so Policy Workbench can draft Python policies from natural language. Drafts are never auto-enabled — analysts still validate, dry-run, and create."
        actions={<StatusBadge status={aiStatus(settings)} />}
      />

      <Card>
        <CardHeader>
          <CardTitle>Policy draft provider</CardTitle>
          <CardDescription>
            API keys are encrypted at rest and never returned after save. Clearing falls back to
            server env or an offline stub.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AiSettingsForm initial={settings} />
        </CardContent>
      </Card>
    </div>
  );
}
