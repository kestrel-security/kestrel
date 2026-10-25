// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  bellAriaLabel,
  markAllReadLocally,
  markReadLocally,
  notificationHref,
  unreadBadgeText,
} from "./notifications";
import type { InAppNotification, InAppNotificationList } from "./types";

function notification(overrides: Partial<InAppNotification> = {}): InAppNotification {
  return {
    id: "n1",
    operator_id: "op",
    kind: "finding",
    event_type: "finding.opened",
    title: "Finding opened: MFA disabled",
    body: "high · MFA disabled",
    finding_id: "f1",
    severity: "high",
    payload: {},
    read_at: null,
    is_read: false,
    detail_path: "/findings/f1",
    created_at: "2026-10-05T09:00:00Z",
    ...overrides,
  };
}

function list(items: InAppNotification[]): InAppNotificationList {
  return {
    items,
    next_cursor: null,
    unread_count: items.filter((item) => !item.is_read).length,
  };
}

const NOW = new Date("2026-10-05T10:00:00Z");

describe("unreadBadgeText", () => {
  it("hides the badge at zero", () => {
    expect(unreadBadgeText(0)).toBeNull();
    expect(unreadBadgeText(-1)).toBeNull();
    expect(unreadBadgeText(Number.NaN)).toBeNull();
  });

  it("caps large counts", () => {
    expect(unreadBadgeText(7)).toBe("7");
    expect(unreadBadgeText(99)).toBe("99");
    expect(unreadBadgeText(100)).toBe("99+");
  });
});

describe("bellAriaLabel", () => {
  it("announces the unread count", () => {
    expect(bellAriaLabel(0)).toBe("Notifications");
    expect(bellAriaLabel(3)).toBe("Notifications, 3 unread");
  });
});

describe("notificationHref", () => {
  it("uses the API detail path for findings and webhooks", () => {
    expect(notificationHref(notification())).toBe("/findings/f1");
    expect(
      notificationHref(notification({ finding_id: null, detail_path: "/settings/webhooks/w1" })),
    ).toBe("/settings/webhooks/w1");
  });

  it("refuses off-site paths and falls back to the finding", () => {
    expect(notificationHref(notification({ detail_path: "//evil.example/x" }))).toBe("/findings/f1");
    expect(notificationHref(notification({ detail_path: "https://evil.example" }))).toBe(
      "/findings/f1",
    );
    expect(notificationHref(notification({ detail_path: null, finding_id: null }))).toBeNull();
  });
});

describe("markReadLocally", () => {
  it("marks one item and decrements the count", () => {
    const before = list([notification({ id: "a" }), notification({ id: "b" })]);
    const after = markReadLocally(before, "a", NOW);
    expect(after.unread_count).toBe(1);
    expect(after.items[0]).toMatchObject({ is_read: true, read_at: NOW.toISOString() });
    expect(after.items[1].is_read).toBe(false);
  });

  it("is idempotent for read or unknown ids", () => {
    const before = list([notification({ id: "a", is_read: true, read_at: "2026-10-01T00:00:00Z" })]);
    expect(markReadLocally(before, "a", NOW)).toBe(before);
    expect(markReadLocally(before, "missing", NOW)).toBe(before);
  });
});

describe("markAllReadLocally", () => {
  it("marks everything read and zeroes the count", () => {
    const earlier = "2026-10-01T00:00:00Z";
    const before = list([
      notification({ id: "a" }),
      notification({ id: "b", is_read: true, read_at: earlier }),
    ]);
    const after = markAllReadLocally(before, NOW);
    expect(after.unread_count).toBe(0);
    expect(after.items.map((item) => item.read_at)).toEqual([NOW.toISOString(), earlier]);
  });
});
