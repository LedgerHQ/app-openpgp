import { ledgerLivePreset } from "@ledgerhq/lumen-design-core";

/** @type {import('tailwindcss').Config} */
export default {
  presets: [ledgerLivePreset],
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
    // Scan lumen's compiled components so Tailwind emits the classes they use.
    "./node_modules/@ledgerhq/lumen-ui-react/dist/**/*.js",
  ],
};
