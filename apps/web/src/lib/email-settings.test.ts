// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { defaultEmailPort, emailPasswordMustBeReentered, emailStatus, emailStatusLabel } from "./email-settings";

describe("defaultEmailPort", () => {
  it("uses the conventional port for each security mode", () => {
    expect(defaultEmailPort("starttls")).toBe(587);
    expect(defaultEmailPort("ssl")).toBe(465);
    expect(defaultEmailPort("none")).toBe(25);
  });
});

describe("emailPasswordMustBeReentered", () => {
  const saved = {
    host: "smtp.example.com",
    port: 587,
    username: "kestrel",
    password_configured: true,
  };
  const unchanged = { host: "smtp.example.com", port: 587, username: "kestrel" };

  it("is false with nothing saved or no password on file", () => {
    expect(emailPasswordMustBeReentered(null, unchanged)).toBe(false);
    expect(emailPasswordMustBeReentered({ ...saved, password_configured: false }, { ...unchanged, host: "other.example" })).toBe(false);
  });

  it("is false when the endpoint and account are unchanged", () => {
    expect(emailPasswordMustBeReentered(saved, unchanged)).toBe(false);
  });

  it("treats host case, a trailing dot, whitespace and a port string as no change", () => {
    expect(
      emailPasswordMustBeReentered(saved, { host: " SMTP.example.com. ", port: "587", username: " kestrel " }),
    ).toBe(false);
  });

  it("flags a changed host, port or username", () => {
    expect(emailPasswordMustBeReentered(saved, { ...unchanged, host: "mail.attacker.example" })).toBe(true);
    expect(emailPasswordMustBeReentered(saved, { ...unchanged, port: 2525 })).toBe(true);
    expect(emailPasswordMustBeReentered(saved, { ...unchanged, username: "someone-else" })).toBe(true);
  });

  it("treats a blank username and a saved null username as the same", () => {
    expect(emailPasswordMustBeReentered({ ...saved, username: null }, { ...unchanged, username: "" })).toBe(false);
  });
});

describe("emailStatus", () => {
  it("maps the source in force to a status and label", () => {
    expect(emailStatus({ source: "org" })).toBe("org");
    expect(emailStatusLabel({ source: "org" })).toBe("Configured in Kestrel");
    expect(emailStatus({ source: "environment" })).toBe("environment");
    expect(emailStatusLabel({ source: "environment" })).toBe("From server environment");
    expect(emailStatus({ source: null })).toBe("not_configured");
    expect(emailStatusLabel({ source: null })).toBe("Not configured");
  });
});
