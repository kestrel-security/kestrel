// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useEffect } from "react";

import "./globals.css";

/**
 * Last-resort boundary for an error in the root layout itself. It replaces
 * that layout, so it renders its own <html>/<body> and depends on nothing but
 * the stylesheet. Fixed copy only, as in app/error.tsx.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-4 p-8">
          <div>
            <h1 className="text-lg font-semibold">Kestrel hit an unexpected error</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Reload to try again. If it keeps happening, the web server log has the details
              {error.digest ? " under the reference below" : ""}.
            </p>
            {error.digest ? (
              <p className="mt-2 font-mono text-xs text-muted-foreground">Reference: {error.digest}</p>
            ) : null}
          </div>
          <div>
            <button
              type="button"
              onClick={() => reset()}
              className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Try again
            </button>
          </div>
        </main>
      </body>
    </html>
  );
}
