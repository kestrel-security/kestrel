// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { themeBlockingScript } from "@/lib/theme";

/**
 * Applies stored theme (or system) before paint to avoid FOUC.
 * Preference: localStorage `kestrel-theme` = system | light | dark.
 */
export function ThemeScript({ nonce }: { nonce?: string }) {
  // Browsers hide a nonce from the DOM after load, so hydration would see a
  // mismatch on the attribute.
  return (
    <script nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: themeBlockingScript() }} />
  );
}
