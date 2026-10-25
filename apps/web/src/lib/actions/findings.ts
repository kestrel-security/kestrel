// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { ApiError, api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type { FindingProvenance, FindingSummary, Page } from "@/lib/types";

type ActionResult = { ok: true } | { ok: false; error: string };

// A Read-only operator gets a 403 from every mutating finding route; say what
// role it takes rather than the API's terse detail.
function findingActionError(err: unknown): string {
  const message = formatActionError(err);
  if (err instanceof ApiError && err.status === 403) {
    return "You don't have permission to do that — this action requires the Analyst role or higher.";
  }
  return message;
}

/** Run a finding mutation; failures come back as `{ok: false}` for inline display. */
async function findingMutation(findingId: string, run: () => Promise<unknown>, paths: string[]): Promise<ActionResult> {
  try {
    await run();
  } catch (err) {
    return { ok: false, error: findingActionError(err) };
  }
  revalidatePath(`/findings/${findingId}`);
  for (const path of paths) revalidatePath(path);
  return { ok: true };
}

export async function updateFindingStatus(findingId: string, status: string): Promise<ActionResult> {
  return findingMutation(
    findingId,
    () => api.patch(`/findings/${segment(findingId)}`, { status }),
    ["/findings"],
  );
}

export async function assignFinding(
  findingId: string,
  assignedToOperatorId: string | null,
): Promise<ActionResult> {
  return findingMutation(
    findingId,
    () => api.patch(`/findings/${segment(findingId)}`, { assigned_to_operator_id: assignedToOperatorId }),
    ["/findings"],
  );
}

/** Next page for cursor-paginated findings list. */
export async function fetchFindingsPage(
  filters: {
    severity?: string;
    status?: string;
    search?: string;
    policy_slug?: string;
    assigned_to_operator_id?: string;
    unassigned?: string;
    open_older_than_days?: string;
    subject_id?: string;
    subject_type?: string;
    application_instance_id?: string;
  },
  cursor: string,
  limit: number,
): Promise<
  | { ok: true; items: FindingSummary[]; next_cursor: string | null }
  | { ok: false; error: string }
> {
  try {
    const query = new URLSearchParams();
    if (filters.severity) query.set("severity", filters.severity);
    if (filters.status) query.set("status", filters.status);
    if (filters.search) query.set("search", filters.search);
    if (filters.policy_slug) query.set("policy_slug", filters.policy_slug);
    if (filters.unassigned === "true" || filters.unassigned === "1") {
      query.set("unassigned", "true");
    } else if (filters.assigned_to_operator_id) {
      query.set("assigned_to_operator_id", filters.assigned_to_operator_id);
    }
    if (filters.open_older_than_days) {
      query.set("open_older_than_days", filters.open_older_than_days);
    }
    if (filters.subject_id) query.set("subject_id", filters.subject_id);
    if (filters.subject_type) query.set("subject_type", filters.subject_type);
    if (filters.application_instance_id) {
      query.set("application_instance_id", filters.application_instance_id);
    }
    query.set("limit", String(limit));
    query.set("cursor", cursor);
    const page = await api.get<Page<FindingSummary>>(
      `/findings?${query.toString()}`,
    );
    return { ok: true, items: page.items, next_cursor: page.next_cursor };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function bulkUpdateFindings(
  findingIds: string[],
  patch: { status?: string; assigned_to_operator_id?: string | null },
): Promise<{ ok: true; updated_count: number } | { ok: false; error: string }> {
  try {
    const result = await api.post<{ updated_count: number }>("/findings/bulk", {
      finding_ids: findingIds,
      ...patch,
    });
    revalidatePath("/findings");
    return { ok: true, updated_count: result.updated_count };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function createFindingException(
  findingId: string,
  reason: string,
  expiresAt: string | null = null,
): Promise<ActionResult> {
  return findingMutation(
    findingId,
    () =>
      api.post(`/findings/${segment(findingId)}/exceptions`, {
        reason,
        expires_at: expiresAt,
      }),
    ["/findings"],
  );
}

export async function addFindingNote(findingId: string, body: string): Promise<ActionResult> {
  return findingMutation(findingId, () => api.post(`/findings/${segment(findingId)}/notes`, { body }), []);
}

export async function muteFinding(
  findingId: string,
  body: { days?: number; muted_until?: string; reason?: string | null },
): Promise<ActionResult> {
  return findingMutation(
    findingId,
    () => api.post(`/findings/${segment(findingId)}/mute`, body),
    ["/findings", "/dashboard"],
  );
}

export async function unmuteFinding(findingId: string): Promise<ActionResult> {
  return findingMutation(
    findingId,
    () => api.post(`/findings/${segment(findingId)}/unmute`, {}),
    ["/findings", "/dashboard"],
  );
}

export async function createFindingTicket(
  findingId: string,
  input: { integration_id: string; dry_run?: boolean },
): Promise<
  | { ok: true; dry_run: true; url: string; external_id: string; provider: string }
  | {
      ok: true;
      dry_run: false;
      ticket: { id: string; url: string; external_id: string; provider: string };
    }
  | { ok: false; error: string }
> {
  try {
    const result = await api.post<{
      dry_run?: boolean;
      url?: string;
      external_id?: string;
      provider?: string;
      ticket?: { id: string; url: string; external_id: string; provider: string } | null;
    }>(`/findings/${segment(findingId)}/tickets`, {
      integration_id: input.integration_id,
      dry_run: Boolean(input.dry_run),
    });
    revalidatePath(`/findings/${findingId}`);
    if (result.dry_run) {
      return {
        ok: true,
        dry_run: true,
        url: result.url ?? "",
        external_id: result.external_id ?? "",
        provider: result.provider ?? "",
      };
    }
    if (!result.ticket) {
      return { ok: false, error: "Ticket create returned no ticket" };
    }
    return { ok: true, dry_run: false, ticket: result.ticket };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function saveFindingPreset(
  name: string,
  filters: Record<string, unknown>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post("/findings/presets", { name, filters });
    revalidatePath("/findings");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function setFindingPresetFavorite(
  presetId: string,
  isFavorite: boolean,
): Promise<ActionResult> {
  try {
    await api.patch(`/findings/presets/${segment(presetId)}`, { is_favorite: isFavorite });
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
  revalidatePath("/findings");
  return { ok: true };
}

/** Bump a preset's "recently used" stamp. Best-effort: callers don't wait on it. */
export async function touchFindingPreset(presetId: string): Promise<ActionResult> {
  try {
    await api.post(`/findings/presets/${segment(presetId)}/use`, {});
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
  revalidatePath("/findings");
  return { ok: true };
}

export async function deleteFindingPreset(presetId: string): Promise<ActionResult> {
  try {
    await api.delete(`/findings/presets/${segment(presetId)}`);
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
  revalidatePath("/findings");
  return { ok: true };
}

/** Subject raw_source provenance for finding evidence browser. */
export async function fetchFindingProvenance(
  findingId: string,
): Promise<
  | { ok: true; provenance: FindingProvenance }
  | { ok: false; error: string }
> {
  try {
    const provenance = await api.get<FindingProvenance>(
      `/findings/${segment(findingId)}/provenance`,
    );
    return { ok: true, provenance };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
