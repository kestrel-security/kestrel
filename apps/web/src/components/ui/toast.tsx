// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { cn } from "@/lib/utils";

export type ToastTone = "success" | "error" | "info";

type Toast = {
  id: number;
  tone: ToastTone;
  message: string;
  /** Extra line under the message: a reason, a count, a next step. */
  detail?: string;
};

type ToastContextValue = {
  toast: (message: string, options?: { tone?: ToastTone; detail?: string }) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const DISMISS_AFTER_MS: Record<ToastTone, number> = {
  // Errors stay until dismissed: the operator has to read them, and a failure
  // that vanishes in four seconds is a failure nobody saw.
  error: 0,
  success: 4000,
  info: 6000,
};

const TONE_STYLES: Record<ToastTone, string> = {
  success: "border-tone-success/40 bg-card",
  error: "border-destructive/50 bg-card",
  info: "border-border bg-card",
};

/**
 * Feedback for actions whose result is not visible on the page.
 *
 * Most server actions in the product either succeed silently (a role change, a
 * schedule saved) or surface a failure only inside the component that fired
 * them. Both are indistinguishable from "nothing happened" while an operator
 * is looking somewhere else on the page.
 *
 * Deliberately dependency-free: this is a list, a timer, and an aria-live
 * region, which is less code than wiring a toast library and leaves nothing to
 * keep up to date.
 */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback<ToastContextValue["toast"]>((message, options) => {
    const tone = options?.tone ?? "success";
    const id = nextId.current++;
    setToasts((current) => [...current.slice(-3), { id, tone, message, detail: options?.detail }]);
  }, []);

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

function ToastViewport({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-full max-w-sm flex-col gap-2"
      role="region"
      aria-label="Notifications"
    >
      {toasts.map((toast) => (
        <ToastRow key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

function ToastRow({ toast, onDismiss }: { toast: Toast; onDismiss: (id: number) => void }) {
  useEffect(() => {
    const ms = DISMISS_AFTER_MS[toast.tone];
    if (!ms) return;
    const timer = setTimeout(() => onDismiss(toast.id), ms);
    return () => clearTimeout(timer);
  }, [toast.id, toast.tone, onDismiss]);

  const Icon = toast.tone === "success" ? CheckCircle2 : toast.tone === "error" ? XCircle : Info;

  return (
    <div
      className={cn(
        "pointer-events-auto flex items-start gap-2 rounded-md border p-3 text-sm shadow-lg",
        TONE_STYLES[toast.tone],
      )}
      role={toast.tone === "error" ? "alert" : "status"}
      aria-live={toast.tone === "error" ? "assertive" : "polite"}
    >
      <Icon
        className={cn(
          "mt-0.5 size-4 shrink-0",
          toast.tone === "success" && "text-tone-success",
          toast.tone === "error" && "text-destructive",
          toast.tone === "info" && "text-muted-foreground",
        )}
        aria-hidden
      />
      <div className="min-w-0 flex-1">
        <p className="font-medium">{toast.message}</p>
        {toast.detail && <p className="mt-0.5 text-xs text-muted-foreground">{toast.detail}</p>}
      </div>
      <button
        type="button"
        onClick={() => onDismiss(toast.id)}
        className="shrink-0 rounded p-0.5 text-muted-foreground transition-colors hover:text-foreground"
        aria-label="Dismiss notification"
      >
        <X className="size-3.5" aria-hidden />
      </button>
    </div>
  );
}

/**
 * Show a toast. Outside a provider this is a no-op rather than a crash, so a
 * component can be rendered in isolation (a test, a story) without one.
 */
export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  return context ?? NOOP;
}

const NOOP: ToastContextValue = { toast: () => undefined };
