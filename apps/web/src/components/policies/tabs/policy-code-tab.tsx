// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { PolicyEditor } from "@/components/policies/policy-editor";
import { api, orFallback, segment } from "@/lib/api";
import type { PolicyDetail, PolicyFixturesResponse } from "@/lib/types";

/**
 * Code & test tab — the authoring surface, given the full page width.
 *
 * Deliberately unwrapped: the editor supplies its own chrome, so a surrounding
 * Card would only add dead padding around it.
 */
export async function PolicyCodeTab({
  policy,
  policyId,
}: {
  policy: PolicyDetail;
  policyId: string;
}) {
  const fixturesPayload = await api
    .get<PolicyFixturesResponse>(`/policies/${segment(policyId)}/fixtures`)
    .catch(orFallback(null));

  const editable = policy.source === "custom";

  const fixturesJson =
    fixturesPayload?.available && fixturesPayload.fixtures
      ? JSON.stringify(fixturesPayload.fixtures, null, 2)
      : null;

  const fixturesLabel =
    fixturesPayload?.available && fixturesPayload.source === "pack" && fixturesPayload.relative_path
      ? `Pack fixture: ${fixturesPayload.relative_path}`
      : fixturesPayload?.available && fixturesPayload.source === "pack"
        ? `Pack fixture (${fixturesPayload.pack_name}/${fixturesPayload.slug})`
        : fixturesPayload?.available && fixturesPayload.source === "custom"
          ? "Saved custom fixtures"
          : null;

  return (
    <PolicyEditor
      mode="edit"
      policyId={policy.id}
      initialSource={policy.source_text ?? ""}
      initialFixtures={fixturesJson}
      fixturesLabel={fixturesLabel}
      fixturesSource={fixturesPayload?.source ?? null}
      editable={editable}
    />
  );
}
