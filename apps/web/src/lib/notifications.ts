// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { InAppNotification, InAppNotificationList } from "@/lib/types";

/** How many recent notifications the nav bell lists. */
export const BELL_LIST_LIMIT = 10;

/** Badge text for an unread count; null hides the badge. */
export function unreadBadgeText(count: number): string | null {
  if (!Number.isFinite(count) || count <= 0) return null;
  return count > 99 ? "99+" : String(Math.floor(count));
}

/** The bell's accessible name, so the count is announced, not just drawn. */
export function bellAriaLabel(count: number): string {
  if (!Number.isFinite(count) || count <= 0) return "Notifications";
  return `Notifications, ${count} unread`;
}

/**
 * Where a notification links. The API sends a `detail_path` (a finding or a
 * webhook page); only same-origin app paths are followed, so a malformed
 * payload can never turn the bell into an open redirect.
 */
export function notificationHref(
  notification: Pick<InAppNotification, "detail_path" | "finding_id">,
): string | null {
  const path = notification.detail_path;
  if (path && path.startsWith("/") && !path.startsWith("//")) return path;
  if (notification.finding_id) return `/findings/${notification.finding_id}`;
  return null;
}

/** Local state after marking one notification read (idempotent). */
export function markReadLocally(
  list: InAppNotificationList,
  id: string,
  now: Date = new Date(),
): InAppNotificationList {
  let changed = false;
  const items = list.items.map((item) => {
    if (item.id !== id || item.is_read) return item;
    changed = true;
    return { ...item, is_read: true, read_at: now.toISOString() };
  });
  if (!changed) return list;
  return { ...list, items, unread_count: Math.max(0, list.unread_count - 1) };
}

/** Local state after "mark all read". */
export function markAllReadLocally(
  list: InAppNotificationList,
  now: Date = new Date(),
): InAppNotificationList {
  const readAt = now.toISOString();
  return {
    ...list,
    items: list.items.map((item) =>
      item.is_read ? item : { ...item, is_read: true, read_at: readAt },
    ),
    unread_count: 0,
  };
}
