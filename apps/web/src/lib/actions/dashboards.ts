// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type { DashboardBoard, DashboardQueryResult, DashboardSchedule, DashboardWidget } from "@/lib/types";

export async function createDashboard(input: {
  name: string;
  slug?: string | null;
  description?: string | null;
  visibility?: string;
  template?: string | null;
}): Promise<
  | { ok: true; dashboard: DashboardBoard }
  | { ok: false; error: string }
> {
  try {
    const dashboard = await api.post<DashboardBoard>("/dashboards", {
      name: input.name,
      slug: input.slug ?? undefined,
      description: input.description ?? undefined,
      visibility: input.visibility ?? "org",
      template: input.template ?? undefined,
    });
    revalidatePath("/dashboard");
    return { ok: true, dashboard };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function duplicateDashboard(
  dashboardId: string,
): Promise<
  | { ok: true; dashboard: DashboardBoard }
  | { ok: false; error: string }
> {
  try {
    const dashboard = await api.post<DashboardBoard>(
      `/dashboards/${segment(dashboardId)}/duplicate`,
    );
    revalidatePath("/dashboard");
    return { ok: true, dashboard };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function deleteDashboard(
  dashboardId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/dashboards/${segment(dashboardId)}`);
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function saveDashboardLayouts(
  dashboardId: string,
  layouts: { id: string; layout: Record<string, unknown>; sort_order?: number }[],
): Promise<
  | { ok: true; dashboard: DashboardBoard }
  | { ok: false; error: string }
> {
  try {
    const dashboard = await api.put<DashboardBoard>(
      `/dashboards/${segment(dashboardId)}/layout`,
      { layouts },
    );
    revalidatePath("/dashboard");
    return { ok: true, dashboard };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function createDashboardWidget(
  dashboardId: string,
  input: {
    widget_key: string;
    title: string;
    viz_type: string;
    query_spec: Record<string, unknown>;
    layout?: { x: number; y: number; w: number; h: number };
    preset_id?: string;
  },
): Promise<
  | { ok: true; widget: DashboardWidget }
  | { ok: false; error: string }
> {
  try {
    const widget = await api.post<DashboardWidget>(
      `/dashboards/${segment(dashboardId)}/widgets`,
      input,
    );
    revalidatePath("/dashboard");
    return { ok: true, widget };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function deleteDashboardWidget(
  dashboardId: string,
  widgetId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/dashboards/${segment(dashboardId)}/widgets/${segment(widgetId)}`);
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function previewDashboardQuery(
  query_spec: Record<string, unknown>,
): Promise<
  | { ok: true; data: DashboardQueryResult }
  | { ok: false; error: string }
> {
  try {
    const data = await api.post<DashboardQueryResult>(
      "/dashboards/query/preview",
      { query_spec },
    );
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function createDashboardSchedule(
  dashboardId: string,
  input: {
    cron: string;
    timezone?: string;
    format?: string;
    recipient_operator_ids: string[];
  },
): Promise<
  | { ok: true; schedule: DashboardSchedule }
  | { ok: false; error: string }
> {
  try {
    let recipients = input.recipient_operator_ids;
    if (!recipients.length) {
      const me = await api.get<{ id: string }>("/auth/me");
      recipients = [me.id];
    }
    const schedule = await api.post<DashboardSchedule>(
      `/dashboards/${segment(dashboardId)}/schedules`,
      { ...input, recipient_operator_ids: recipients },
    );
    revalidatePath("/dashboard");
    return { ok: true, schedule };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function pinDashboardHome(
  dashboardId: string | null,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post("/dashboards/pin-home", {
      dashboard_id: dashboardId,
    });
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** POST /dashboard/first-run/dismiss — hides the getting-started checklist for this operator. */
export async function dismissFirstRun(): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post("/dashboard/first-run/dismiss");
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** POST /dashboard/first-run/restore — shows the checklist again (until setup completes). */
export async function restoreFirstRun(): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post("/dashboard/first-run/restore");
    revalidatePath("/dashboard");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
