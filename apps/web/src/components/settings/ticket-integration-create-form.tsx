// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { createTicketIntegration } from "@/lib/actions/integrations";

export function TicketIntegrationCreateForm() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [provider, setProvider] = useState("github_issues");

  // onSubmit rather than <form action>: React resets a form after its action
  // runs, which wiped every field (the token included) when the server
  // rejected the input. The form is cleared only once the create succeeds.
  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    setError(null);
    const selected = String(formData.get("provider") ?? "github_issues");
    const config: Record<string, unknown> =
      selected === "jira_cloud"
        ? {
            base_url: String(formData.get("base_url") ?? ""),
            project_key: String(formData.get("project_key") ?? ""),
            email: String(formData.get("email") ?? ""),
            issue_type: String(formData.get("issue_type") ?? "") || "Task",
          }
        : { repo: String(formData.get("repo") ?? "") };

    startTransition(async () => {
      const result = await createTicketIntegration({
        name: String(formData.get("name") ?? ""),
        provider: selected,
        api_token: String(formData.get("api_token") ?? ""),
        description: String(formData.get("description") ?? "") || null,
        config,
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      form.reset();
      router.refresh();
    });
  }

  return (
    <form onSubmit={onSubmit} className="space-y-3">
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="space-y-1.5">
        <Label htmlFor="ticket-name">Name</Label>
        <Input id="ticket-name" name="name" required />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="ticket-provider">Provider</Label>
        <input type="hidden" name="provider" value={provider} />
        <Select value={provider} onValueChange={setProvider}>
          <SelectTrigger id="ticket-provider">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="github_issues">GitHub Issues</SelectItem>
            <SelectItem value="jira_cloud">Jira Cloud</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {provider === "github_issues" ? (
        <div className="space-y-1.5">
          <Label htmlFor="ticket-repo">GitHub repo (owner/repo)</Label>
          <Input id="ticket-repo" name="repo" required placeholder="acme/security-ops" />
        </div>
      ) : (
        <>
          <div className="space-y-1.5">
            <Label htmlFor="ticket-base-url">Jira base URL</Label>
            <Input
              id="ticket-base-url"
              name="base_url"
              type="url"
              required
              placeholder="https://acme.atlassian.net"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ticket-project-key">Project key</Label>
            <Input id="ticket-project-key" name="project_key" required placeholder="SEC" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ticket-email">Atlassian account email</Label>
            <Input id="ticket-email" name="email" type="email" required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ticket-issue-type">Issue type</Label>
            <Input id="ticket-issue-type" name="issue_type" defaultValue="Task" />
          </div>
        </>
      )}
      <div className="space-y-1.5">
        <Label htmlFor="ticket-api-token">API token (encrypted at rest; never shown again)</Label>
        <Input id="ticket-api-token" name="api_token" type="password" required minLength={8} autoComplete="off" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="ticket-description">Description</Label>
        <Input id="ticket-description" name="description" />
      </div>
      <Button type="submit" size="sm" disabled={pending}>
        {pending ? "Creating…" : "Create integration"}
      </Button>
    </form>
  );
}
