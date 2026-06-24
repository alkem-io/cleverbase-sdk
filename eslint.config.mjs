// Enforcing flat ESLint config for the SDK's JavaScript/TypeScript surface:
// the TS frontend helper, the no-crypto reference web frontend, the Node binding tests, and the
// JS/MJS demos. Generated and build artifacts are excluded.
//
// Strictness target: the strictest practical TypeScript surface. The TS blocks extend
// typescript-eslint's `strictTypeChecked` + `stylisticTypeChecked` presets (full type-aware
// linting), and the helper's exported public API is additionally held to documented-and-valid
// TSDoc so the TypeDoc API docs stay accurate.
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import tsdoc from "eslint-plugin-tsdoc";
import jsdoc from "eslint-plugin-jsdoc";

// Computed from import.meta.url for portability across Node versions (import.meta.dirname
// is only available on newer runtimes).
const rootDir = dirname(fileURLToPath(import.meta.url));

// Rules shared by every type-checked TypeScript block (helper + web). Kept in one place so the
// two surfaces cannot drift (DRY).
const strictTsRules = {
  // Unused symbols are errors; a leading underscore is the explicit "intentionally unused" opt-out.
  "@typescript-eslint/no-unused-vars": [
    "error",
    {
      argsIgnorePattern: "^_",
      varsIgnorePattern: "^_",
      caughtErrorsIgnorePattern: "^_",
    },
  ],
  // No untyped escape hatch anywhere in the TS surface.
  "@typescript-eslint/no-explicit-any": "error",
  // Promises must be awaited/handled and never passed where a non-promise is expected.
  "@typescript-eslint/no-floating-promises": "error",
  "@typescript-eslint/no-misused-promises": "error",
  // Public function/method signatures must be explicitly typed (feeds clear API docs).
  "@typescript-eslint/explicit-module-boundary-types": "error",
  // `import type` everywhere a binding is type-only, enforced as a fixable separate statement.
  "@typescript-eslint/consistent-type-imports": [
    "error",
    { prefer: "type-imports", fixStyle: "separate-type-imports" },
  ],
  "@typescript-eslint/consistent-type-exports": "error",
  // Catch silent stringification of non-strings into template literals / strings.
  "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
  eqeqeq: ["error", "always"],
};

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
    // Plain JS/MJS/CJS (binding tests + demos) run on Node.
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
    // CommonJS binding tests use `require`/`module`; allow the CommonJS globals there.
    files: ["**/*.cjs"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { ...globals.node, ...globals.commonjs },
    },
  },
  {
    // The TypeScript frontend helper, fully type-checked with the strictest presets.
    files: ["frontend/helper-ts/src/**/*.ts"],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    plugins: { tsdoc, jsdoc },
    languageOptions: {
      parserOptions: {
        project: "./frontend/helper-ts/tsconfig.json",
        tsconfigRootDir: rootDir,
      },
    },
    rules: {
      ...strictTsRules,
      // The helper is a published library whose TSDoc feeds the TypeDoc API reference: every
      // exported declaration MUST be documented, and the comment syntax MUST be valid TSDoc.
      "tsdoc/syntax": "error",
      "jsdoc/require-jsdoc": [
        "error",
        {
          // Only the exported public surface; `publicOnly` skips non-exported helpers.
          publicOnly: true,
          require: {
            ClassDeclaration: true,
            FunctionDeclaration: true,
            MethodDefinition: true,
          },
          contexts: [
            // Exported types/interfaces themselves.
            "ExportNamedDeclaration > TSInterfaceDeclaration",
            "ExportNamedDeclaration > TSTypeAliasDeclaration",
            // Their direct members only — `TSInterfaceBody >` excludes nested/inline object type
            // literals (e.g. internal callback shapes), which are not public API.
            "TSInterfaceBody > TSPropertySignature",
            "TSInterfaceBody > TSMethodSignature",
            // Public class members (declared properties) reached via an exported class.
            "PropertyDefinition",
          ],
          // TSDoc owns tag syntax/validation; jsdoc only enforces presence here.
          enableFixer: false,
        },
      ],
      "jsdoc/require-description": ["error", { contexts: ["any"] }],
    },
  },
  {
    // The no-crypto reference web frontend, type-checked against its own tsconfig (DOM libs, no
    // Node types). Not a published library, so doc-comment presence is not enforced here, but it
    // gets the same strict type-aware rule set.
    files: ["examples/reference-integration/web/src/**/*.ts"],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    plugins: { tsdoc },
    languageOptions: {
      parserOptions: {
        project: "./examples/reference-integration/web/tsconfig.json",
        tsconfigRootDir: rootDir,
      },
    },
    rules: {
      ...strictTsRules,
      // Validate any TSDoc the demo does carry, without requiring it.
      "tsdoc/syntax": "error",
    },
  },
);
