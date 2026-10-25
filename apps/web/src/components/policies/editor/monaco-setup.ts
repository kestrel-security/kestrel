// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor";

/**
 * Point `@monaco-editor/react` at the Monaco bundled with this app instead of
 * its default, a script tag loading an unpinned build from cdn.jsdelivr.net
 * (no integrity check, and a third-party origin the CSP would have to allow).
 *
 * Browser-only: Monaco touches `window` at import time. source-editor.tsx
 * imports this module from a `next/dynamic` loader with `ssr: false`, so it
 * is never evaluated on the server and its chunk loads only on pages that
 * show an editor.
 *
 * Workers are same-origin module chunks the bundler emits from the
 * `new Worker(new URL(...))` pattern. The JSON worker validates the fixtures
 * editor; Python has tokenization only, so everything else gets the generic
 * editor worker.
 */
self.MonacoEnvironment = {
  getWorker(_workerId: string, label: string) {
    if (label === "json") {
      return new Worker(new URL("monaco-editor/language/json/json.worker", import.meta.url), {
        type: "module",
      });
    }
    return new Worker(new URL("monaco-editor/editor/editor.worker", import.meta.url), {
      type: "module",
    });
  },
};

loader.config({ monaco });
