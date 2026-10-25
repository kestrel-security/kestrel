// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useCallback, useSyncExternalStore } from "react";

import {
  SIDEBAR_EVENT,
  SIDEBAR_STORAGE_KEY,
  getStoredCollapsed,
  setStoredCollapsed,
} from "@/lib/sidebar";

function subscribe(onStoreChange: () => void): () => void {
  const onSidebar = () => onStoreChange();
  const onStorage = (event: StorageEvent) => {
    if (event.key === SIDEBAR_STORAGE_KEY || event.key === null) onStoreChange();
  };
  window.addEventListener(SIDEBAR_EVENT, onSidebar);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(SIDEBAR_EVENT, onSidebar);
    window.removeEventListener("storage", onStorage);
  };
}

function getSnapshot(): boolean {
  return getStoredCollapsed();
}

function getServerSnapshot(): boolean {
  return false;
}

/**
 * Only the toggle button itself should consume this — everything else
 * (width, label visibility) is pure CSS driven by the pre-paint blocking
 * script (see `SidebarScript` / globals.css `[data-sidebar-collapsed]`) so
 * there's no post-hydration flash. This hook has the same one-frame
 * hydration-catchup window `useTheme` already has for `ThemeToggle`.
 */
export function useSidebarCollapsed(): { collapsed: boolean; toggle: () => void } {
  const collapsed = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const toggle = useCallback(() => {
    setStoredCollapsed(!getStoredCollapsed());
  }, []);
  return { collapsed, toggle };
}
