import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { HashRouter } from "react-router";

import { queryClient } from "./queryClient";

import { App } from "./App";
import { installTheme } from "./theme";
import "./styles.css";

installTheme();

const container = document.getElementById("root");
if (!container) {
  throw new Error("index.html has no #root element");
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <App />
      </HashRouter>
    </QueryClientProvider>
  </StrictMode>,
);
