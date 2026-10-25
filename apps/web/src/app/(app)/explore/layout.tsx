// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Full-bleed identity graph workbench: cancels main's padding (p-4, md:p-6) and fills the height left by the mobile top bar (h-14). */
export default function ExploreLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="-m-4 flex h-[calc(100vh-3.5rem)] min-h-0 md:-m-6 md:h-screen flex-col overflow-hidden bg-[hsl(var(--background))]">
      {children}
    </div>
  );
}
