// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { retryWebhookDelivery } from "@/lib/actions/integrations";

export function RetryWebhookDeliveryButton({
  webhookId,
  deliveryId,
}: {
  webhookId: string;
  deliveryId: string;
}) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  if (done) {
    return <span className="text-xs text-muted-foreground">Queued</span>;
  }

  return (
    <div>
      {error && <p className="mb-1 text-xs text-destructive">{error}</p>}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-6 px-2 text-[11px]"
        disabled={pending}
        onClick={() => {
          setError(null);
          startTransition(async () => {
            const result = await retryWebhookDelivery(webhookId, deliveryId);
            if (!result.ok) {
              setError(result.error);
              return;
            }
            setDone(true);
          });
        }}
      >
        {pending ? "Retrying…" : "Retry"}
      </Button>
    </div>
  );
}
