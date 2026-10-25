// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { unstable_rethrow } from "next/navigation";

import { PolicyNewWorkbench } from "@/components/policies/policy-new-workbench";
import { AppPage } from "@/components/ui/app-page";
import { PageHeader } from "@/components/ui/page-header";
import { api } from "@/lib/api";
import type { ConnectorInstanceSummary, PolicyGenerateCatalog } from "@/lib/types";

const STARTER = `POLICY_ID = "my-custom-policy"
TITLE = "Name the condition this policy flags"
SEVERITY = "medium"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Describe the desired state and what deviates from it"
REMEDIATION = "Require MFA for this identity."


def policy(resource):
    identity = resource.get("identity") or {}
    # Return True if compliant; False opens a finding.
    return bool(identity.get("mfa_enabled"))


def evidence(resource):
    identity = resource.get("identity") or {}
    return {
        "identity.email": identity.get("email"),
        "identity.display_name": identity.get("display_name"),
    }
`;

export default async function NewPolicyPage() {
  let connectors: ConnectorInstanceSummary[] = [];
  let initialCatalog: PolicyGenerateCatalog | null = null;
  try {
    connectors = await api.get<ConnectorInstanceSummary[]>("/connector-instances");
    const okta = connectors.find((c) => c.connector_name === "okta");
    if (okta) {
      initialCatalog = await api.get<PolicyGenerateCatalog>(
        `/policies/generate/catalog?application_instance_id=${okta.application_instance_id}`,
      );
    }
  } catch (error) {
    unstable_rethrow(error);
    connectors = [];
  }

  return (
    <AppPage className="space-y-6">
      <PageHeader
        eyebrow="Policies"
        title="New custom policy"
        description="Author Python policy logic in the browser. Validate and fixture-test before publishing; the slug comes from POLICY_ID."
      />

      <PolicyNewWorkbench
        starterSource={STARTER}
        connectors={connectors}
        initialCatalog={initialCatalog}
      />
    </AppPage>
  );
}
