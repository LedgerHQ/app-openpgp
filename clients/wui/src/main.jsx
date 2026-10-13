import "./buffer.js";
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { isFramed } from "./framing.js";
import "./index.css";

const root = document.getElementById("root");
// Never render the device actions inside another page, which could hide them
if (isFramed()) {
  root.textContent = "This page cannot be displayed inside another page.";
} else {
  createRoot(root).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}
