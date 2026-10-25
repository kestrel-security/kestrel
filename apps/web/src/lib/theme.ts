// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
export const THEME_STORAGE_KEY = "kestrel-theme";
export const THEME_EVENT = "kestrel:theme";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export type ThemeChangeDetail = {
  theme: ThemePreference;
  resolvedTheme: ResolvedTheme;
};

const VALID: ReadonlySet<string> = new Set(["system", "light", "dark"]);

export function isThemePreference(value: unknown): value is ThemePreference {
  return typeof value === "string" && VALID.has(value);
}

export function getSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  if (preference === "system") return getSystemTheme();
  return preference;
}

export function getStoredTheme(): ThemePreference {
  if (typeof window === "undefined") return "system";
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (isThemePreference(raw)) return raw;
  } catch {
    /* private mode / blocked storage */
  }
  return "system";
}

/** Apply preference to <html>: `.dark` class + `color-scheme`. */
export function applyTheme(preference: ThemePreference): ResolvedTheme {
  const resolved = resolveTheme(preference);
  const root = document.documentElement;
  if (resolved === "dark") {
    root.classList.add("dark");
  } else {
    root.classList.remove("dark");
  }
  root.style.colorScheme = resolved;
  return resolved;
}

export function setStoredTheme(preference: ThemePreference): ResolvedTheme {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    /* ignore */
  }
  const resolvedTheme = applyTheme(preference);
  window.dispatchEvent(
    new CustomEvent<ThemeChangeDetail>(THEME_EVENT, {
      detail: { theme: preference, resolvedTheme },
    }),
  );
  return resolvedTheme;
}

/** Inline blocking script — keep in sync with helpers above. */
export function themeBlockingScript(): string {
  return `(() => {
  try {
    var KEY = ${JSON.stringify(THEME_STORAGE_KEY)};
    var root = document.documentElement;
    var mq = window.matchMedia("(prefers-color-scheme: light)");
    function read() {
      try {
        var v = localStorage.getItem(KEY);
        if (v === "light" || v === "dark" || v === "system") return v;
      } catch (e) {}
      return "system";
    }
    function resolve(pref) {
      if (pref === "light" || pref === "dark") return pref;
      return mq.matches ? "light" : "dark";
    }
    function apply(pref) {
      var resolved = resolve(pref);
      if (resolved === "dark") root.classList.add("dark");
      else root.classList.remove("dark");
      root.style.colorScheme = resolved;
    }
    apply(read());
    // Do not attach matchMedia listeners here — Next 15's overlay treats
    // those Event objects as unhandled rejections ([object Event]).
    // Live OS changes are handled by useTheme after hydration.
  } catch (e) {}
})();`;
}
