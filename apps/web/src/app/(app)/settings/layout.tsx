// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { SettingsNav } from "@/components/settings/settings-nav";
import { api } from "@/lib/api";
import type { Operator } from "@/lib/types";

export default async function SettingsLayout({ children }: { children: React.ReactNode }) {
  const operator = await api.get<Operator>("/auth/me");

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Manage your account preferences and organization configuration.
        </p>
      </div>
      <div className="flex flex-col gap-8 sm:flex-row sm:items-start">
        <aside className="w-full shrink-0 sm:sticky sm:top-6 sm:w-44">
          <SettingsNav role={operator.role} />
        </aside>
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </div>
  );
}
