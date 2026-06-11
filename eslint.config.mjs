// Minimal ESLint flat config for the LiteZero simulator.
// Enforces strict TypeScript semantics and forbids unsafe patterns that could
// compromise reproducibility or constant-time behaviour.

import tseslint from "typescript-eslint";

export default tseslint.config({
  files: ["src/**/*.ts", "scripts/**/*.ts"],
  extends: [...tseslint.configs.recommended],
  languageOptions: {
    parserOptions: {
      project: "./tsconfig.json",
    },
  },
  rules: {
    // Reproducibility / crypto hygiene guardrails.
    "no-console": "off",
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
    // Math.random is banned — use randomFloat() / randomBytes() from rng.ts so
    // the seeded-CSPRNG path is respected. We also forbid direct require() of
    // node:crypto's randomBytes in non-rng.ts files (enforced in review).
    "no-restricted-syntax": [
      "error",
      {
        selector:
          "CallExpression[callee.object.name='Math'][callee.property.name='random']",
        message: "Use randomFloat() from src/crypto/rng.ts — Math.random is not seeded.",
      },
    ],
  },
});
