// Dev only: installs the mock when the app runs in a plain browser (`pnpm dev`). It is never part of a release build.
// Start state by URL: `?mock=unlocked` (default), `?mock=sealed`, `?mock=no_vault`, `?mock=locking`; `&role=viewer`;
// `&lock_reason=idle` sets why the vault was locked (manual, idle, max_unlocked, os, quit, panic, restore).
// `&backend=remote` runs as a desktop in remote mode (ADR-0034); `&remote_problem=remote_unreachable` (or
// remote_pin_mismatch, remote_protocol_mismatch, admin_cert_required) makes the server fail.
// In the console: `__cerberusMock.setState("sealed")`.
import type { LockReasonView, OperatorRole, VaultState } from "../../bindings";
import { emit } from "@tauri-apps/api/event";
import { installMock, type MockController, type MockHandlers } from "./core";

declare global {
  interface Window {
    __cerberusMock?: MockController;
  }
}

const STATES: readonly VaultState[] = ["unlocked", "sealed", "no_vault", "locking"];
const ROLES: readonly OperatorRole[] = ["owner", "operator", "viewer"];
const LOCK_REASONS: readonly LockReasonView[] = ["manual", "idle", "max_unlocked", "os", "quit", "panic", "restore"];

/** Each screen folder may add `mock.ts` with `export const handlers: MockHandlers`. They are merged here. */
const screenMocks = import.meta.glob<{ handlers: MockHandlers }>("../../screens/*/mock.ts", { eager: true });

/** The handlers of each screen mock, by file path. */
export const screenSources = (): Record<string, MockHandlers> => Object.fromEntries(Object.entries(screenMocks).map(([path, m]) => [path, m.handlers]));

/** Joins the sources. A command must have one owner: two answers would hide each other, so this throws. */
export function mergeHandlers(sources: Record<string, MockHandlers>): MockHandlers {
  const merged: MockHandlers = {};
  const owners = new Map<string, string>();
  for (const [source, handlers] of Object.entries(sources)) {
    for (const [command, handler] of Object.entries(handlers)) {
      const first = owners.get(command);
      if (first !== undefined) throw new Error(`The dev mock answers ${command} in ${first} and in ${source}`);
      owners.set(command, source);
      merged[command] = handler;
    }
  }
  return merged;
}

export function installDevMock(): MockController {
  const params = new URLSearchParams(window.location.search);
  const state = STATES.find((s) => s === params.get("mock")) ?? "unlocked";
  const role = ROLES.find((r) => r === params.get("role")) ?? "owner";
  const lockReason = LOCK_REASONS.find((r) => r === params.get("lock_reason")) ?? null;
  const problem = params.get("remote_problem");
  const remote = params.get("backend") === "remote" ? (problem ? { reachable: problem === "admin_cert_required", problem } : true) : undefined;
  const ctl = installMock({ state, role, lockReason, ...(remote ? { remote } : {}), handlers: mergeHandlers(screenSources()) });
  window.__cerberusMock = ctl;
  // The idle timer ticks once a second while the vault is open, like the real pump.
  window.setInterval(() => {
    if (ctl.state === "unlocked" && ctl.idleSecondsLeft !== null) {
      ctl.idleSecondsLeft = Math.max(0, ctl.idleSecondsLeft - 1);
      void emit("autolock-tick", { seconds_left: ctl.idleSecondsLeft });
    }
  }, 1000);
  return ctl;
}
