// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import type { ConnectorAuthMethod, ConnectorCatalogEntry } from "@/lib/types";

function normalizeWhitespace(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

export function ConnectorSetupGuide({
  connector,
  authMethod,
}: {
  connector: ConnectorCatalogEntry | null;
  authMethod: ConnectorAuthMethod | null;
}) {
  if (!connector || !authMethod) return null;

  const steps = authMethod.setup_steps ?? [];
  const overview = authMethod.setup_overview
    ? normalizeWhitespace(authMethod.setup_overview)
    : null;
  const scopesNote = authMethod.scopes_note
    ? normalizeWhitespace(authMethod.scopes_note)
    : null;
  const scopes = connector.required_scopes ?? [];

  if (!overview && steps.length === 0 && scopes.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-border px-3 py-2 text-xs text-muted-foreground">
        This connector has not published a setup walkthrough yet. See the connector package README
        or ask your admin for credential instructions.
      </div>
    );
  }

  return (
    <Card className="bg-muted/30">
      <CardHeader className="space-y-1">
        <p className="text-eyebrow">Setup guide</p>
        <h2 className="text-sm font-medium">
          {connector.display_name} · {authMethod.label}
        </h2>
        {overview && <p className="text-xs text-muted-foreground">{overview}</p>}
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {scopes.length > 0 && (
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">Required scopes / permissions</p>
            {scopesNote && <p className="text-xs text-muted-foreground">{scopesNote}</p>}
            <ul className="flex flex-wrap gap-1.5">
              {scopes.map((scope) => (
                <li
                  key={scope}
                  className="rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px]"
                >
                  {scope}
                </li>
              ))}
            </ul>
          </div>
        )}

        {steps.length > 0 && (
          <ol className="space-y-3">
            {steps.map((step, index) => (
              <li key={`${step.title}-${index}`} className="flex gap-2">
                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-foreground text-[11px] font-medium text-background">
                  {index + 1}
                </span>
                <div className="min-w-0 space-y-1">
                  <p className="text-xs font-medium">{step.title}</p>
                  <p className="text-xs text-muted-foreground">{normalizeWhitespace(step.body)}</p>
                  {step.link_url && (
                    <a
                      href={step.link_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-block text-xs text-primary underline"
                    >
                      {step.link_label?.trim() || "Open provider console"}
                    </a>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}

        {connector.setup_docs && (
          <p className="text-[11px] text-muted-foreground">
            Long-form docs: <code className="rounded bg-muted px-1 font-mono">{connector.setup_docs}</code>
          </p>
        )}
      </CardContent>
    </Card>
  );
}
