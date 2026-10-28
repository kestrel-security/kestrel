// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { api, segment, slugSegment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type { PolicyDryRunResult, PolicyEvaluateResult, PolicyFixtureCaptureResult, PolicyFixtureTestResult, PolicyFixturesResponse, PolicyGenerateCatalog, PolicyGenerateResult, PolicyValidateResult } from "@/lib/types";

export async function createCustomPolicy(
  sourceText: string,
): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  try {
    const policy = await api.post<{ id: string }>("/policies", { source_text: sourceText });
    revalidatePath("/policies");
    return { ok: true, id: policy.id };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function publishPolicyVersion(
  policyId: string,
  sourceText: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/policies/${segment(policyId)}/versions`, { source_text: sourceText });
    revalidatePath(`/policies/${policyId}`);
    revalidatePath("/policies");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function setPolicyEnabled(policyId: string, isEnabled: boolean) {
  await api.patch(`/policies/${segment(policyId)}`, { is_enabled: isEnabled });
  revalidatePath(`/policies/${policyId}`);
  revalidatePath("/policies");
}

/** `setPolicyEnabled` with a result instead of a throw, for client components. */
export async function togglePolicyEnabled(
  policyId: string,
  isEnabled: boolean,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await setPolicyEnabled(policyId, isEnabled);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** DELETE /policies/{id} — permanent; takes versions, evaluations, and findings with it. */
export async function deletePolicy(
  policyId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/policies/${segment(policyId)}`);
    revalidatePath("/policies");
    revalidatePath("/policies/packs");
    revalidatePath("/findings");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** POST /policies/{id}/evaluate — mutate reconcile; distinct from dry-run. */
export async function evaluatePolicyNow(policyId: string) {
  const result = await api.post<PolicyEvaluateResult>(
    `/policies/${segment(policyId)}/evaluate`,
    {},
  );
  revalidatePath(`/policies/${policyId}`);
  revalidatePath("/policies");
  revalidatePath("/findings");
  return result;
}

/** POST /policies/{id}/fork — pack → disabled custom copy. */
export async function forkPackPolicy(policyId: string) {
  const forked = await api.post<{ id: string }>(`/policies/${segment(policyId)}/fork`, {});
  revalidatePath("/policies");
  revalidatePath(`/policies/${policyId}`);
  revalidatePath(`/policies/${forked.id}`);
  return forked;
}

/** POST /policies/{id}/versions/{versionId}/activate — custom rollback. */
export async function activatePolicyVersion(policyId: string, versionId: string) {
  await api.post(`/policies/${segment(policyId)}/versions/${segment(versionId)}/activate`, {});
  revalidatePath(`/policies/${policyId}`);
  revalidatePath("/policies");
}

export async function installPack(
  packName: string,
  profile?: string | null,
): Promise<{ ok: true; count: number } | { ok: false; error: string }> {
  try {
    const body = profile ? { profile } : undefined;
    const installed = await api.post<PolicySummaryLike[]>(
      `/packs/${slugSegment(packName)}/install`,
      body,
    );
    revalidatePath("/policies");
    revalidatePath("/policies/packs");
    revalidatePath(`/policies/packs/${packName}`);
    return { ok: true, count: installed.length };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function enablePack(
  packName: string,
): Promise<{ ok: true; count: number } | { ok: false; error: string }> {
  try {
    const result = await api.post<{ policies_updated: number }>(
      `/packs/${slugSegment(packName)}/enable`,
      {},
    );
    revalidatePath("/policies");
    revalidatePath(`/policies/packs/${packName}`);
    return { ok: true, count: result.policies_updated };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function disablePack(
  packName: string,
): Promise<{ ok: true; count: number } | { ok: false; error: string }> {
  try {
    const result = await api.post<{ policies_updated: number }>(
      `/packs/${slugSegment(packName)}/disable`,
      {},
    );
    revalidatePath("/policies");
    revalidatePath(`/policies/packs/${packName}`);
    return { ok: true, count: result.policies_updated };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

type PolicySummaryLike = { id: string };

export async function generatePolicyDraft(input: {
  intent: string;
  resource_type?: string;
  connector_hint?: string;
  application_instance_id?: string;
  include_fixtures?: boolean;
  scope?: "single_app" | "cross_app";
}): Promise<
  | { ok: true; result: PolicyGenerateResult }
  | { ok: false; error: string }
> {
  try {
    const result = await api.post<PolicyGenerateResult>("/policies/generate", {
      intent: input.intent,
      resource_type: input.resource_type,
      connector_hint: input.connector_hint,
      application_instance_id: input.application_instance_id,
      include_fixtures: input.include_fixtures ?? true,
      scope: input.scope,
    });
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function fetchPolicyGenerateCatalog(params: {
  connector_hint?: string;
  application_instance_id?: string;
  scope?: "single_app" | "cross_app";
}): Promise<
  | { ok: true; catalog: PolicyGenerateCatalog }
  | { ok: false; error: string }
> {
  try {
    const search = new URLSearchParams();
    if (params.connector_hint) search.set("connector_hint", params.connector_hint);
    if (params.application_instance_id) search.set("application_instance_id", params.application_instance_id);
    if (params.scope) search.set("scope", params.scope);
    const qs = search.toString();
    const catalog = await api.get<PolicyGenerateCatalog>(
      `/policies/generate/catalog${qs ? `?${qs}` : ""}`,
    );
    return { ok: true, catalog };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function validatePolicySource(
  sourceText: string,
): Promise<
  | { ok: true; result: PolicyValidateResult }
  | { ok: false; error: string }
> {
  try {
    const result = await api.post<PolicyValidateResult>("/policies/validate", {
      source_text: sourceText,
    });
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function testPolicyFixtures(
  policyId: string | null,
  sourceText: string,
  fixturesJson: string,
): Promise<
  | { ok: true; result: PolicyFixtureTestResult }
  | { ok: false; error: string }
> {
  let fixtures: Record<string, unknown>;
  try {
    fixtures = JSON.parse(fixturesJson) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "Fixtures must be valid JSON" };
  }
  try {
    const result = policyId
      ? await api.post<PolicyFixtureTestResult>(`/policies/${segment(policyId)}/test`, {
          fixtures,
          source_text: sourceText,
        })
      : await api.post<PolicyFixtureTestResult>("/policies/test-draft", {
          fixtures,
          source_text: sourceText,
        });
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function dryRunPolicyLive(
  policyId: string | null,
  sourceText: string,
): Promise<
  | { ok: true; result: PolicyDryRunResult }
  | { ok: false; error: string }
> {
  try {
    const result = policyId
      ? await api.post<PolicyDryRunResult>(`/policies/${segment(policyId)}/dry-run`, {
          source_text: sourceText,
        })
      : await api.post<PolicyDryRunResult>("/policies/dry-run-draft", {
          source_text: sourceText,
        });
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function savePolicyFixtures(
  policyId: string,
  fixturesJson: string,
): Promise<
  | { ok: true; result: PolicyFixturesResponse }
  | { ok: false; error: string }
> {
  let fixtures: Record<string, unknown> | null;
  const trimmed = fixturesJson.trim();
  if (!trimmed) {
    fixtures = null;
  } else {
    try {
      fixtures = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      return { ok: false, error: "Fixtures must be valid JSON" };
    }
  }
  try {
    const result = await api.put<PolicyFixturesResponse>(
      `/policies/${segment(policyId)}/fixtures`,
      { fixtures },
    );
    revalidatePath(`/policies/${policyId}`);
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function captureFixturesFromMatches(
  policyId: string | null,
  sourceText: string,
  subjectIds: string[],
  options?: { persist?: boolean; maxRows?: number },
): Promise<
  | { ok: true; result: PolicyFixtureCaptureResult }
  | { ok: false; error: string }
> {
  const body = {
    source_text: sourceText,
    subject_ids: subjectIds,
    max_rows: options?.maxRows ?? 50,
    persist: options?.persist ?? false,
  };
  try {
    const result = policyId
      ? await api.post<PolicyFixtureCaptureResult>(
          `/policies/${segment(policyId)}/fixtures/from-matches`,
          body,
        )
      : await api.post<PolicyFixtureCaptureResult>(
          "/policies/fixtures/from-matches",
          body,
        );
    if (policyId && options?.persist) {
      revalidatePath(`/policies/${policyId}`);
    }
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
