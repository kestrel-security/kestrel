// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { sidebarBlockingScript } from "@/lib/sidebar";

/**
 * Applies a stored sidebar-collapsed preference before paint to avoid a
 * flash of the expanded rail. Preference: localStorage `kestrel-sidebar-collapsed`.
 */
export function SidebarScript({ nonce }: { nonce?: string }) {
  return (
    <script nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: sidebarBlockingScript() }} />
  );
}
