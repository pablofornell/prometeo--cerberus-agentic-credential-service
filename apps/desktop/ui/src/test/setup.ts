import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { clearMocks } from "@tauri-apps/api/mocks";
import { afterEach, expect } from "vitest";
import * as axeMatchers from "vitest-axe/matchers";
import { createFlowStore } from "../shell/createFlow";
import { overlayStore } from "../shell/uiStore";
import { agentFeedStore, alertsStore, autolockStore, vaultStateStore } from "../state/live";

expect.extend(axeMatchers);

// Suites run in parallel: the first render and axe can be slow on a busy machine.
configure({ asyncUtilTimeout: 8000 });

afterEach(() => {
  cleanup();
  clearMocks();
  window.location.hash = "";
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  vaultStateStore.set("unknown");
  overlayStore.set("none");
  createFlowStore.set(false);
  autolockStore.set(null);
  agentFeedStore.set([]);
  alertsStore.set({ massRead: [], integrity: [], headerMismatch: false });
});

// jsdom has no canvas. axe tries it for colour contrast and logs a warning; contrast is checked on the tokens (docs/ux/check-contrast.mjs).
HTMLCanvasElement.prototype.getContext = () => null;
