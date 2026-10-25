// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
export const SIDEBAR_STORAGE_KEY = "kestrel-sidebar-collapsed";
export const SIDEBAR_EVENT = "kestrel:sidebar";

export type SidebarChangeDetail = {
  collapsed: boolean;
};

export function getStoredCollapsed(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === "true";
  } catch {
    /* private mode / blocked storage */
  }
  return false;
}

/** Apply state to <html>: `data-sidebar-collapsed` attribute (see globals.css). */
export function applyCollapsed(collapsed: boolean): void {
  const root = document.documentElement;
  if (collapsed) {
    root.setAttribute("data-sidebar-collapsed", "true");
  } else {
    root.removeAttribute("data-sidebar-collapsed");
  }
}

export function setStoredCollapsed(collapsed: boolean): void {
  try {
    window.localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "true" : "false");
  } catch {
    /* ignore */
  }
  applyCollapsed(collapsed);
  window.dispatchEvent(
    new CustomEvent<SidebarChangeDetail>(SIDEBAR_EVENT, { detail: { collapsed } }),
  );
}

/** Inline blocking script — keep in sync with helpers above. */
export function sidebarBlockingScript(): string {
  return `(() => {
  try {
    var KEY = ${JSON.stringify(SIDEBAR_STORAGE_KEY)};
    var collapsed = false;
    try {
      collapsed = localStorage.getItem(KEY) === "true";
    } catch (e) {}
    if (collapsed) document.documentElement.setAttribute("data-sidebar-collapsed", "true");
  } catch (e) {}
})();`;
}
