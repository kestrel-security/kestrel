// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Field defaults for the new-connector wizard, kept out of the component so
 * switching connector or auth method is testable.
 */

import type { ConnectorAuthMethod, ConnectorCatalogEntry } from "@/lib/types";

/**
 * The auth method `id` names on `entry`, or the connector's first one. A
 * stale id (left from the previous connector, or the empty value a Radix
 * Select reports while its options are swapped) never leaves the form with
 * no method selected.
 */
export function resolveAuthMethod(
  entry: ConnectorCatalogEntry | null | undefined,
  id: string | null | undefined,
): ConnectorAuthMethod | null {
  if (!entry) return null;
  return entry.auth_methods.find((m) => m.id === id) ?? entry.auth_methods[0] ?? null;
}

/** Config fields the method asks for, or the connector's example keys when it lists none. */
export function connectorConfigFields(
  entry: ConnectorCatalogEntry,
  method: ConnectorAuthMethod | null,
): string[] {
  return method?.config_fields.length ? method.config_fields : Object.keys(entry.example_config ?? {});
}

function exampleValue(entry: ConnectorCatalogEntry, field: string): string {
  const value = entry.example_config?.[field];
  return value == null ? "" : String(value);
}

/**
 * Config values for `method`'s fields. `keep` carries over what the operator
 * already typed when only the auth method changes on the same connector;
 * omit it when the connector changes, since another connector's values mean
 * nothing here.
 */
export function connectorConfigValues(
  entry: ConnectorCatalogEntry,
  method: ConnectorAuthMethod | null,
  keep: Record<string, string> = {},
): Record<string, string> {
  const values: Record<string, string> = {};
  for (const field of connectorConfigFields(entry, method)) {
    values[field] = keep[field] ?? exampleValue(entry, field);
  }
  return values;
}

export type ConnectorFormDefaults = {
  authMethod: string;
  configValues: Record<string, string>;
  displayName: string;
  externalTenantRef: string;
};

/** Everything connector-specific the wizard should show right after `entry` is picked. */
export function connectorFormDefaults(entry: ConnectorCatalogEntry): ConnectorFormDefaults {
  const method = resolveAuthMethod(entry, null);
  const primary = method?.config_fields[0];
  return {
    authMethod: method?.id ?? "",
    configValues: connectorConfigValues(entry, method),
    displayName: entry.display_name,
    externalTenantRef: primary ? exampleValue(entry, primary) : "",
  };
}

/**
 * A free-text field's value after the connector changes: the new default
 * unless the operator typed something of their own (anything other than empty
 * or the previous connector's default).
 */
export function followDefault(current: string, previousDefault: string | undefined, nextDefault: string): string {
  return current.trim() === "" || current === previousDefault ? nextDefault : current;
}
