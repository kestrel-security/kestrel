// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import { BELL_LIST_LIMIT } from "@/lib/notifications";
import type { InAppNotificationList, WatchDigestPreview } from "@/lib/types";

/** Update the calling operator's notification preferences. */
export async function updateNotificationPreferences(input: {
  email_enabled: boolean;
  in_app_enabled: boolean;
  findings_enabled: boolean;
  webhook_failures_enabled: boolean;
  min_severity: string;
  muted_events: string[];
}): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.patch("/notification-preferences", input);
    revalidatePath("/settings/notifications");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Watch a finding: its open/resolve events reach you on every enabled channel, plus the weekly digest. */
export async function watchFinding(findingId: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/findings/${segment(findingId)}/watch`, {});
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
  revalidatePath(`/findings/${findingId}`);
  return { ok: true };
}

/** Stop watching a finding. */
export async function unwatchFinding(findingId: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/findings/${segment(findingId)}/watch`);
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
  revalidatePath(`/findings/${findingId}`);
  return { ok: true };
}

/** What the weekly watched-findings digest would email the caller. Sends nothing. */
export async function previewWatchDigest(): Promise<
  { ok: true; data: WatchDigestPreview } | { ok: false; error: string }
> {
  try {
    const data = await api.post<WatchDigestPreview>("/findings/watched/digest-preview", {});
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** The caller's most recent notifications and unread count, for the nav bell. */
export async function listRecentNotifications(
  limit = BELL_LIST_LIMIT,
): Promise<{ ok: true; data: InAppNotificationList } | { ok: false; error: string }> {
  try {
    const data = await api.get<InAppNotificationList>(`/notifications?limit=${limit}`);
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Mark one of the caller's notifications read. */
export async function markNotificationRead(
  notificationId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/notifications/${segment(notificationId)}/read`, {});
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Mark all of the caller's notifications read. */
export async function markAllNotificationsRead(): Promise<
  { ok: true } | { ok: false; error: string }
> {
  try {
    await api.post("/notifications/read-all", {});
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
