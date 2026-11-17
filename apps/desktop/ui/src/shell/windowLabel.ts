import { getCurrentWindow } from "@tauri-apps/api/window";

export type WindowLabel = "main" | "approval";

/** The label of this window. In a plain browser (dev, tests) it comes from the URL: `#approval` is the approval window. */
export function windowLabel(): WindowLabel {
  try {
    const label = getCurrentWindow().label;
    return label === "approval" ? "approval" : "main";
  } catch {
    return /^#\/?approval\b/.test(window.location.hash) ? "approval" : "main";
  }
}
