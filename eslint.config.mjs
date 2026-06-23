// Enforcing flat ESLint config for the SDK's JavaScript/TypeScript surface:
// the TS frontend helper, the Node binding tests, and the JS/MJS demos. Generated and
// build artifacts are excluded.
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

// Computed from import.meta.url for portability across Node versions (import.meta.dirname
// is only available on newer runtimes).
const rootDir = dirname(fileURLToPath(import.meta.url));

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/target/**",
      "**/.venv/**",
      "**/.git/**",
      "bindings/node/index.js",
      "bindings/node/index.d.ts",
      "bindings/node/npm/**",
    ],
  },
  js.configs.recommended,
  {
    // Plain JS/MJS/CJS (tests + demos) run on Node.
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.node },
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-var": "error",
      "prefer-const": "error",
      eqeqeq: ["error", "always"],
    },
  },
  {
    // The TypeScript frontend helper, type-checked.
    files: ["frontend/helper-ts/src/**/*.ts"],
    extends: [...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: {
        project: "./frontend/helper-ts/tsconfig.json",
        tsconfigRootDir: rootDir,
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      eqeqeq: ["error", "always"],
    },
  },
);
