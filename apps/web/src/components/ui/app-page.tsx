// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** Standard content width for list and settings pages (Explore stays full-bleed). */
export function AppPage({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("mx-auto w-full max-w-7xl", className)}>{children}</div>;
}
