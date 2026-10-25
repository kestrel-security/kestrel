// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
// Shared between proxy.ts (the Next proxy, no next/headers) and
// lib/api.ts / lib/actions/* (server-only) -- kept as a bare string
// constant with zero Node-specific imports so both can use it.
export const SESSION_COOKIE_NAME = "kestrel_session";

// The path the browser asked for, set by proxy.ts on every request it
// lets through, so lib/api.ts can send a 401 back to /login?next=<path>.
export const REQUEST_PATH_HEADER = "x-kestrel-request-path";

// This request's CSP nonce, set by proxy.ts (overwriting anything the
// client sent) for the root layout's inline boot scripts.
export const NONCE_HEADER = "x-nonce";
