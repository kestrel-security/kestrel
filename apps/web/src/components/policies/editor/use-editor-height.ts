// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useCallback, useEffect, useState } from "react";

export const EDITOR_HEIGHT_STORAGE_KEY = "kestrel.policy-editor.height";
export const MIN_EDITOR_HEIGHT = 280;
export const MAX_EDITOR_HEIGHT = 1200;
export const DEFAULT_EDITOR_HEIGHT = 520;
/** Keyboard nudge for the resize separator. */
export const EDITOR_HEIGHT_STEP = 24;

export function clampEditorHeight(value: number): number {
  if (!Number.isFinite(value)) return DEFAULT_EDITOR_HEIGHT;
  return Math.min(MAX_EDITOR_HEIGHT, Math.max(MIN_EDITOR_HEIGHT, Math.round(value)));
}

function readStoredHeight(): number | null {
  try {
    const raw = window.localStorage.getItem(EDITOR_HEIGHT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? clampEditorHeight(parsed) : null;
  } catch {
    // Private-mode / blocked storage: fall back to the default silently.
    return null;
  }
}

/**
 * Editor pane height, persisted per browser.
 *
 * Reads storage after mount rather than during render so SSR and the first
 * client paint agree — same shape as `use-sidebar-collapsed`.
 */
export function useEditorHeight(): {
  height: number;
  setHeight: (next: number) => void;
  resetHeight: () => void;
} {
  const [height, setHeightState] = useState(DEFAULT_EDITOR_HEIGHT);

  useEffect(() => {
    const stored = readStoredHeight();
    if (stored != null) setHeightState(stored);
  }, []);

  const setHeight = useCallback((next: number) => {
    const clamped = clampEditorHeight(next);
    setHeightState(clamped);
    try {
      window.localStorage.setItem(EDITOR_HEIGHT_STORAGE_KEY, String(clamped));
    } catch {
      // Height is a convenience, never a correctness concern.
    }
  }, []);

  const resetHeight = useCallback(() => setHeight(DEFAULT_EDITOR_HEIGHT), [setHeight]);

  return { height, setHeight, resetHeight };
}
