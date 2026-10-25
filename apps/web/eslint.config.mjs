// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = [
  { ignores: ["node_modules/**", ".next/**", "next-env.d.ts"] },
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    // eslint-config-next 16 turns on react-hooks v7's React Compiler rules.
    // This app does not use the React Compiler, and these flag established,
    // working patterns (resetting state when a prop changes, reading the
    // clock while rendering a relative time), so they stay off rather than
    // forcing rewrites of code that behaves correctly.
    rules: {
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/purity": "off",
      "react-hooks/static-components": "off",
    },
  },
];

export default config;
