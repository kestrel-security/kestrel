// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import path from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Pure logic tests, mostly under `src/lib/` (node environment, no DOM).
// There are no component or browser tests yet; see "Frontend" in
// docs/testing.md. `@vitejs/plugin-react` is wired up so a jsdom project
// can be added later without re-plumbing config.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
    passWithNoTests: false,
  },
});
