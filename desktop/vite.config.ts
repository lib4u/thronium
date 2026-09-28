import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// @ts-expect-error type error without @types/node package
import process from "node:process";
import languages from "./locales/languages.json" with { type: "json" };
import { defaults } from "./src/shared/api/generated/defaults.ts";
const host = process.env.TAURI_DEV_HOST;

// The page before the first snapshot: the manifest's source language and the default theme.
const initialDocument = {
  name: "initial-document",
  transformIndexHtml: (html: string) =>
    html.replace("%SOURCE_LANGUAGE%", languages.source).replace("%DEFAULT_THEME%", defaults.preferences.theme),
};

// https://vite.dev/config/
export default defineConfig(() => ({
  plugins: [react(), initialDocument],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
