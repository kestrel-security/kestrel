// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * The server's password policy (kestrel/src/kestrel/auth/passwords.py):
 * length only, per NIST 800-63B, with no composition rules. The API enforces
 * it; this copy lets the form say what's wrong before a round trip.
 */
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

export const PASSWORD_POLICY_HINT = `${MIN_PASSWORD_LENGTH}–${MAX_PASSWORD_LENGTH} characters. Any characters are allowed; a long passphrase is easier to remember than a short complex password.`;

/** Length as Python counts it (code points), so emoji count once, as on the server. */
function passwordLength(value: string): number {
  return Array.from(value).length;
}

/** Why `password` would be refused by the server's policy, or null when it is fine. */
export function newPasswordProblem(password: string): string | null {
  const length = passwordLength(password);
  if (length < MIN_PASSWORD_LENGTH) {
    return `The new password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (length > MAX_PASSWORD_LENGTH) {
    return `The new password must be at most ${MAX_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

/** The first problem with a change-password submission, or null when it can be sent. */
export function changePasswordProblem(input: {
  current: string;
  next: string;
  confirm: string;
}): string | null {
  if (!input.current) return "Enter your current password.";
  const problem = newPasswordProblem(input.next);
  if (problem) return problem;
  if (input.next !== input.confirm) return "The new passwords don't match.";
  if (input.next === input.current) return "The new password must differ from the current one.";
  return null;
}

// No 0/O or 1/l/I: a temporary password is often read aloud or retyped.
const TEMPORARY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/** A random temporary password for an admin reset, from the platform CSPRNG. */
export function generateTemporaryPassword(length = 20): string {
  const out: string[] = [];
  // Rejection sampling keeps every character equally likely.
  const limit = 256 - (256 % TEMPORARY_ALPHABET.length);
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && out.length < length) out.push(TEMPORARY_ALPHABET[byte % TEMPORARY_ALPHABET.length]);
    }
  }
  return out.join("");
}
