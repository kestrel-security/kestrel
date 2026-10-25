// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { blocksActionShortcut, blocksNavigationShortcut } from "@/lib/keyboard-targets";

/** A stand-in element that "is within" the given selector parts. */
function el(...matches: string[]) {
  return {
    closest(selector: string) {
      const parts = selector.split(",").map((s) => s.trim());
      return parts.some((p) => matches.includes(p)) ? this : null;
    },
  };
}

describe("blocksActionShortcut", () => {
  it("blocks links, buttons, menu items, checkboxes and dialogs", () => {
    for (const sel of ["a[href]", "button", "[role=menuitem]", "[role=option]", "[role=checkbox]", "[role=dialog]"]) {
      expect(blocksActionShortcut(el(sel))).toBe(true);
    }
  });

  it("blocks typing targets", () => {
    expect(blocksActionShortcut(el("input"))).toBe(true);
    expect(blocksActionShortcut(el("textarea"))).toBe(true);
  });

  it("allows the page body and plain rows", () => {
    expect(blocksActionShortcut(el())).toBe(false);
    expect(blocksActionShortcut(null)).toBe(false);
    expect(blocksActionShortcut(window_like())).toBe(false);
  });
});

describe("blocksNavigationShortcut", () => {
  it("lets j/k work from a link or row checkbox", () => {
    expect(blocksNavigationShortcut(el("a[href]"))).toBe(false);
    expect(blocksNavigationShortcut(el("[role=checkbox]"))).toBe(false);
  });

  it("leaves arrow keys to menus, listboxes and dialogs", () => {
    expect(blocksNavigationShortcut(el("[role=menu]"))).toBe(true);
    expect(blocksNavigationShortcut(el("[role=listbox]"))).toBe(true);
    expect(blocksNavigationShortcut(el("[role=dialog]"))).toBe(true);
    expect(blocksNavigationShortcut(el("input"))).toBe(true);
  });
});

/** `window` / `document` have no closest(). */
function window_like() {
  return {};
}
