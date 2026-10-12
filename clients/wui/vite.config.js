import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// https://vite.dev/config/
export default defineConfig({
  // Relative base so the build works under the /wui/ sub-path of the Pages site.
  base: "./",
  // Open the browser automatically when the dev server starts.
  server: { open: true },
  plugins: [
    react(),
    // The APDU/TLV layer uses the Node Buffer API; expose a browser polyfill.
    nodePolyfills({ include: ["buffer"], globals: { Buffer: true } }),
  ],
  test: {
    globals: true,
    environment: "jsdom",
  },
});
