// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useCallback, useSyncExternalStore } from "react";

import {
  THEME_EVENT,
  THEME_STORAGE_KEY,
  applyTheme,
  getStoredTheme,
  setStoredTheme,
  type ResolvedTheme,
  type ThemePreference,
} from "@/lib/theme";

function subscribe(onStoreChange: () => void): () => void {
  const onTheme = () => onStoreChange();
  const onStorage = (event: StorageEvent) => {
    if (event.key === THEME_STORAGE_KEY || event.key === null) onStoreChange();
  };
  const mq = window.matchMedia("(prefers-color-scheme: light)");
  const onOsChange = () => {
    if (getStoredTheme() === "system") {
      applyTheme("system");
      onStoreChange();
    }
  };

  window.addEventListener(THEME_EVENT, onTheme);
  window.addEventListener("storage", onStorage);
  mq.addEventListener("change", onOsChange);
  return () => {
    window.removeEventListener(THEME_EVENT, onTheme);
    window.removeEventListener("storage", onStorage);
    mq.removeEventListener("change", onOsChange);
  };
}

function getSnapshot(): ThemePreference {
  return getStoredTheme();
}

function getServerSnapshot(): ThemePreference {
  return "system";
}

function getResolvedSnapshot(): ResolvedTheme {
  if (typeof document === "undefined") return "dark";
  // Prefer live class (ThemeScript / applyTheme) over re-resolving.
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

function getResolvedServerSnapshot(): ResolvedTheme {
  return "dark";
}

function subscribeResolved(onStoreChange: () => void): () => void {
  const root = document.documentElement;
  const observer = new MutationObserver(onStoreChange);
  observer.observe(root, { attributes: true, attributeFilter: ["class"] });

  const onTheme = () => onStoreChange();
  window.addEventListener(THEME_EVENT, onTheme);

  const mq = window.matchMedia("(prefers-color-scheme: light)");
  const onOsChange = () => {
    if (getStoredTheme() === "system") onStoreChange();
  };
  mq.addEventListener("change", onOsChange);

  return () => {
    observer.disconnect();
    window.removeEventListener(THEME_EVENT, onTheme);
    mq.removeEventListener("change", onOsChange);
  };
}

export function useTheme(): {
  theme: ThemePreference;
  resolvedTheme: ResolvedTheme;
  setTheme: (preference: ThemePreference) => void;
} {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const resolvedTheme = useSyncExternalStore(
    subscribeResolved,
    getResolvedSnapshot,
    getResolvedServerSnapshot,
  );

  const setTheme = useCallback((preference: ThemePreference) => {
    setStoredTheme(preference);
  }, []);

  return { theme, resolvedTheme, setTheme };
}

/** Resolved light/dark from the document class (for canvases that need it). */
export function useResolvedTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribeResolved, getResolvedSnapshot, getResolvedServerSnapshot);
}
