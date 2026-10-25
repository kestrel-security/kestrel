// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/toast";
import { fetchLatestConnectorRun, triggerConnectorSync } from "@/lib/actions/connectors";

const POLL_MS = 2000;
const DEMO_SYNC_HINT =
  "Demo data comes from `kestrel demo up` and `kestrel demo change`; a sync here would replace it with the small bundled sample.";
const MAX_POLLS = 900; // 30 minutes at 2s -- matches the worker's lock TTL

type Phase = "idle" | "queued" | "running" | "done" | "error";

function describeRun(run: { status: string; objects_total?: number; object_counts?: Record<string, number> }) {
  const total =
    typeof run.objects_total === "number"
      ? run.objects_total
      : Object.values(run.object_counts ?? {}).reduce((sum, n) => sum + n, 0);
  if (run.status === "success") return `Sync finished — ${total.toLocaleString()} objects collected.`;
  if (run.status === "partial_failure") return `Sync finished with reduced coverage — ${total.toLocaleString()} objects collected.`;
  if (run.status === "failed") return "Sync failed. Open the run for details.";
  return "Sync running…";
}

/**
 * "Sync now" with feedback. Enqueues the sync, then polls the latest run until
 * it leaves RUNNING so the page reflects the outcome without a manual refresh.
 */
export function SyncNowButton({
  connectorInstanceId,
  variant = "default",
  compact = false,
  isDemo = false,
}: {
  connectorInstanceId: string;
  variant?: "default" | "secondary" | "outline";
  compact?: boolean;
  /** Demo instances are refreshed by `kestrel demo change`, never synced from here. */
  isDemo?: boolean;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [pending, startTransition] = useTransition();
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [runPath, setRunPath] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const pollsRef = useRef(0);
  const startedAtRef = useRef<string | null>(null);

  useEffect(() => {
    if (phase !== "queued" && phase !== "running") return;
    const timer = setTimeout(async () => {
      pollsRef.current += 1;
      let latest: Awaited<ReturnType<typeof fetchLatestConnectorRun>>;
      try {
        latest = await fetchLatestConnectorRun(connectorInstanceId);
      } catch {
        // The action redirected (session expired, MFA enrolment required):
        // the router is already navigating away, so stop rather than re-arm.
        setPhase("idle");
        return;
      }
      if (!latest.ok && latest.stop) {
        setPhase("error");
        setMessage(latest.error);
        return;
      }
      if (latest.ok && latest.run) {
        const run = latest.run;
        const isNew = !startedAtRef.current || (run.started_at ?? "") >= startedAtRef.current;
        if (isNew && run.status !== "running") {
          const failed = run.status === "failed";
          setPhase(failed ? "error" : "done");
          setMessage(describeRun(run));
          setRunPath(run.detail_path ?? `/connectors/runs/${run.id}`);
          toast(failed ? "Sync failed" : "Sync finished", {
            tone: failed ? "error" : "success",
            detail: describeRun(run),
          });
          router.refresh();
          return;
        }
        if (isNew && run.status === "running") {
          setPhase("running");
          setMessage("Sync running…");
        }
      }
      if (pollsRef.current >= MAX_POLLS) {
        setPhase("error");
        setMessage("Stopped waiting for the sync to finish; check the run history.");
        return;
      }
      setPhase((p) => (p === "queued" ? "queued" : "running"));
      // Re-arm by touching state so the effect runs again.
      setTick((t) => t + 1);
    }, POLL_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, tick]);

  function onClick() {
    setMessage(null);
    setRunPath(null);
    pollsRef.current = 0;
    startedAtRef.current = new Date(Date.now() - 5000).toISOString();
    startTransition(async () => {
      const outcome = await triggerConnectorSync(connectorInstanceId);
      if (!outcome.ok) {
        setPhase(outcome.alreadyRunning ? "running" : "error");
        setMessage(outcome.error);
        if (!outcome.alreadyRunning) toast("Could not start the sync", { tone: "error", detail: outcome.error });
        if (outcome.alreadyRunning) {
          // Attach to the run that is already going.
          startedAtRef.current = null;
          setTick((t) => t + 1);
        }
        return;
      }
      setPhase("queued");
      setMessage("Sync queued…");
      setTick((t) => t + 1);
    });
  }

  const busy = pending || phase === "queued" || phase === "running";

  return (
    <div className="space-y-2">
      <Button
        type="button"
        size="sm"
        variant={variant}
        onClick={onClick}
        disabled={busy || isDemo}
        aria-busy={busy}
        title={isDemo ? DEMO_SYNC_HINT : undefined}
      >
        {busy ? (
          <>
            <Loader2 className="mr-1.5 size-3.5 animate-spin" aria-hidden />
            {phase === "queued" ? "Queued…" : "Syncing…"}
          </>
        ) : (
          "Sync now"
        )}
      </Button>
      {message && !compact && (
        <p
          className={`flex items-start gap-1.5 text-sm ${
            phase === "error"
              ? "text-destructive"
              : phase === "done"
                ? "text-green-800 dark:text-green-400"
                : "text-muted-foreground"
          }`}
          role="status"
        >
          {phase === "done" ? (
            <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          ) : phase === "error" ? (
            <XCircle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          ) : (
            <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin" aria-hidden />
          )}
          <span>
            {message}
            {runPath && (
              <>
                {" "}
                <a className="underline" href={runPath}>
                  View run
                </a>
              </>
            )}
          </span>
        </p>
      )}
    </div>
  );
}
