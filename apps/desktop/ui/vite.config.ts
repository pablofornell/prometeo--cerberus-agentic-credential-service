/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects the dev server on port 1420 (see apps/desktop/src-tauri/tauri.conf.json).
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    // The audit catalog test reads docs/reference/audit-events.md (`?raw`) to check every event type has a phrase.
    fs: { allow: [".", "../../../docs/reference"] },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
    css: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
