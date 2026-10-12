import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// Content Security Policy of the built page: every resource comes from the WUI origin. Styles
// stay inline-capable for the <style> elements the dialog components insert at run time.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

// Add the CSP to the built page only: the dev server needs inline scripts.
const contentSecurityPolicy = {
  name: "content-security-policy",
  apply: "build",
  transformIndexHtml: () => [
    { tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: CSP }, injectTo: "head-prepend" },
  ],
};

// https://vite.dev/config/
export default defineConfig({
  // Relative base so the build works under the /wui/ sub-path of the Pages site.
  base: "./",
  // Open the browser automatically when the dev server starts.
  server: { open: true },
  plugins: [
    react(),
    contentSecurityPolicy,
    // The APDU/TLV layer uses the Node Buffer API; expose a browser polyfill.
    nodePolyfills({ include: ["buffer"], globals: { Buffer: true } }),
  ],
  test: {
    globals: true,
    environment: "jsdom",
  },
});
