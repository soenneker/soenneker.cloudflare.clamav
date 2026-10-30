import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
export default defineConfig({
  plugins: [cloudflareTest({
    main: "./src/index.ts",
    miniflare: {
      compatibilityDate: "2026-10-29", compatibilityFlags: ["nodejs_compat"],
      d1Databases: ["JOBS"], r2Buckets: ["UPLOADS"], queueProducers: { SCANS: "test-scans" },
      bindings: { SCANNER_API_KEY: "test-scanner-key-with-at-least-32-characters" }
    }
  })],
  test: { fileParallelism: false, testTimeout: 20000 }
});
