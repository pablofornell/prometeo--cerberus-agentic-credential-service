import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/index.css";

const container = document.getElementById("root");
if (container === null) {
  throw new Error("Missing #root element in index.html");
}

// In a plain browser during development there is no Tauri runtime. The dev mock answers the commands so a
// screen can be built and photographed without the Rust side (`pnpm dev`, then open the URL; see DEC-T16-6).
async function boot(): Promise<void> {
  if (import.meta.env.DEV && !("__TAURI_INTERNALS__" in window)) {
    const { installDevMock } = await import("./ipc/mock/dev");
    installDevMock();
  }
  createRoot(container!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void boot();
