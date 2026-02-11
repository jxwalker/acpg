module.exports = {
  root: true,
  env: {
    browser: true,
    es2020: true,
  },
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  plugins: ["@typescript-eslint", "react-hooks", "react-refresh"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
  ],
  ignorePatterns: ["dist/", "node_modules/"],
  rules: {
    // We use Vite + React; allow constant exports (components are still hot-reloadable)
    "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

    // This repo already relies on TypeScript strict mode for most correctness checks.
    // Keep ESLint focused on high-signal issues; allow `any` in the large prototype UI.
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/no-unused-vars": "off",
    "react-hooks/exhaustive-deps": "off",
  },
};
