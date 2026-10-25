// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useEffect } from "react";

import { AppPage } from "@/components/ui/app-page";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Route-level error boundary. A failed fetch used to surface as the framework's
 * default overlay in development and a blank screen in production; this keeps
 * the operator inside the product with a way to retry.
 */
export default function AppError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <AppPage>
      <Card className="mx-auto mt-12 max-w-xl">
        <CardHeader>
          <CardTitle>Something went wrong loading this page</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            {error.message || "The API did not return a usable response."}
          </p>
          {error.digest && <p className="text-xs text-muted-foreground">Reference: {error.digest}</p>}
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={reset}>
              Try again
            </Button>
            <Button asChild size="sm" variant="outline">
              <a href="/dashboard">Back to dashboard</a>
            </Button>
          </div>
        </CardContent>
      </Card>
    </AppPage>
  );
}
