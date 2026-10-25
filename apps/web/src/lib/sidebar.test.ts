// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  SIDEBAR_STORAGE_KEY,
  applyCollapsed,
  sidebarBlockingScript,
} from "./sidebar.ts";

describe("sidebarBlockingScript", () => {
  it("embeds the storage key and data-sidebar-collapsed attribute", () => {
    const script = sidebarBlockingScript();
    expect(script.includes(SIDEBAR_STORAGE_KEY)).toBeTruthy();
    expect(script.includes("data-sidebar-collapsed")).toBeTruthy();
    expect(script.includes('localStorage.getItem(KEY) === "true"')).toBeTruthy();
  });
});

describe("applyCollapsed", () => {
  it("sets and removes data-sidebar-collapsed on the document element", () => {
    const previous = globalThis.document;
    const attrs = new Map<string, string>();
    const root = {
      setAttribute(name: string, value: string) {
        attrs.set(name, value);
      },
      removeAttribute(name: string) {
        attrs.delete(name);
      },
      getAttribute(name: string) {
        return attrs.get(name) ?? null;
      },
    };
    // Node unit tests have no DOM; stub the minimal surface applyCollapsed uses.
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { documentElement: root },
    });

    try {
      applyCollapsed(true);
      expect(root.getAttribute("data-sidebar-collapsed")).toBe("true");
      applyCollapsed(false);
      expect(root.getAttribute("data-sidebar-collapsed")).toBe(null);
    } finally {
      if (previous === undefined) {
        // @ts-expect-error restore absent DOM
        delete globalThis.document;
      } else {
        Object.defineProperty(globalThis, "document", {
          configurable: true,
          value: previous,
        });
      }
    }
  });
});
