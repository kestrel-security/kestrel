// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { ConnectorCreateForm } from "@/components/connectors/connector-create-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { apiStatePage } from "@/components/api-state";
import { api } from "@/lib/api";
import type { ConnectorCatalogEntry } from "@/lib/types";

export default async function NewConnectorPage() {
  let catalog: ConnectorCatalogEntry[] = [];
  try {
    catalog = await api.get<ConnectorCatalogEntry[]>("/connectors");
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    throw error;
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <p className="text-sm text-muted-foreground">
        <Link href="/connectors" className="hover:underline">
          Integrations
        </Link>{" "}
        / New
      </p>
      <PageHeader
        eyebrow="Integrations"
        title="Add integration"
        description="Guided builder with a per-connector setup walkthrough: create the provider API key / PAT / App, fill config, paste secrets (envelope-encrypted), then schedule. Prefer fixture mode for offline demos."
        className="mb-0"
      />

      <Card>
        <CardHeader>
          <CardTitle>Instance</CardTitle>
          <CardDescription>Choose a connector, then follow the setup guide on the right.</CardDescription>
        </CardHeader>
        <CardContent>
          <ConnectorCreateForm catalog={catalog} />
        </CardContent>
      </Card>
    </div>
  );
}
