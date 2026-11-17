// A fake backend for the browser and for tests. It answers the IPC commands with fake data only.
// `installMock` uses the official `mockIPC` of @tauri-apps/api, so the real `commands` and `events` run on top of it.
import { emit } from "@tauri-apps/api/event";
import { mockIPC } from "@tauri-apps/api/mocks";
import type { IpcError_Serialize, ItemFilterView_Deserialize, LockReasonView, OperatorRole, VaultState, VaultStatusView_Serialize } from "../../bindings";
import { FIXTURE_KDF, filterItems, fixtureAgents, fixtureItems, fixtureLeases, fixtureNetwork, fixtureRequests, fixtureSettings, fixtureWorkspaces, MOCK_OPERATORS } from "./fixtures";

export type MockArgs = Record<string, unknown> | undefined;
/** A handler returns the data of a command, or throws `mockError(...)`. */
export type MockHandler = (args: MockArgs, ctl: MockController) => unknown;
export type MockHandlers = Record<string, MockHandler>;

export function mockError(code: string, message: string, extra: Partial<IpcError_Serialize> = {}): IpcError_Serialize {
  return { code, message, retry_after_seconds: null, fields: [], ...extra };
}

export interface MockController {
  state: VaultState;
  role: OperatorRole;
  idleSecondsLeft: number | null;
  /** Why the latest lock happened (`vault_status.last_lock_reason`). It stays after an unlock, like the backend. */
  lockReason: LockReasonView | null;
  /** Failed unlocks in a row (`vault_status.failed_unlocks`). A screen mock changes it. */
  failedUnlocks: number;
  /** Time (ms since 1970) when the next unlock try is allowed, or `null` when no wait runs. */
  retryUntil: number | null;
  /** Old vault files of a failed restore (`vault_status.stranded_restore`). Empty in a normal run. */
  stranded: string[];
  /** Changes the vault state and sends `vault-state-changed`, like the real backend. */
  setState: (state: VaultState) => Promise<void>;
  /** Sends one backend event by its name. */
  emit: (event: string, payload: unknown) => Promise<void>;
}

export interface MockOptions {
  state?: VaultState;
  role?: OperatorRole;
  lockReason?: LockReasonView | null;
  /** Old vault files of a failed restore: the status reports them and the state should be `no_vault`. */
  stranded?: string[];
  /** Extra or replacing handlers. Screen folders add theirs in `src/screens/<id>/mock.ts`. */
  handlers?: MockHandlers;
}

/** Wrong tries in a row before the backend makes the person wait (`FREE_UNLOCK_FAILURES`). */
export const FREE_UNLOCK_FAILURES = 5;

export function installMock(options: MockOptions = {}): MockController {
  const ctl: MockController = {
    state: options.state ?? "unlocked",
    role: options.role ?? "owner",
    idleSecondsLeft: 1661,
    lockReason: options.lockReason ?? null,
    failedUnlocks: 0,
    retryUntil: null,
    stranded: options.stranded ?? [],
    setState: async (state) => {
      ctl.state = state;
      await emit("vault-state-changed", { state });
    },
    emit: (event, payload) => emit(event, payload),
  };

  const status = (): VaultStatusView_Serialize => ({
    state: ctl.state,
    operator: ctl.state === "unlocked" ? "op-ana" : null,
    role: ctl.state === "unlocked" ? ctl.role : null,
    idle_seconds_left: ctl.state === "unlocked" ? ctl.idleSecondsLeft : null,
    hard_lock_at: null,
    memlock_ok: true,
    os_hook_ok: true,
    header_ok: true,
    kdf: ctl.state === "unlocked" ? FIXTURE_KDF : null,
    last_lock_reason: ctl.lockReason,
    failed_unlocks: ctl.failedUnlocks,
    free_unlock_tries_left: Math.max(0, FREE_UNLOCK_FAILURES - ctl.failedUnlocks),
    retry_after_seconds: ctl.retryUntil === null || ctl.retryUntil <= Date.now() ? null : Math.ceil((ctl.retryUntil - Date.now()) / 1000),
    stranded_restore: ctl.stranded,
  });

  const open = (): void => {
    if (ctl.state !== "unlocked") throw mockError("vault_locked", "the vault is locked");
  };

  // The base answers every command a screen reads, from the shared fixtures. Screen mocks replace the ones they own.
  const base: MockHandlers = {
    vault_status: () => status(),
    vault_list_operators: () => MOCK_OPERATORS,
    vault_unlock: async (_args, c) => {
      c.failedUnlocks = 0;
      c.retryUntil = null;
      await c.setState("unlocked");
      return { operator_id: "op-ana", role: "owner", unlocked_at: new Date().toISOString(), via_recovery: false };
    },
    vault_lock: async (_args, c) => {
      c.lockReason = "manual";
      await c.setState("sealed");
      return null;
    },
    vault_panic: async (_args, c) => {
      c.lockReason = "panic";
      await c.setState("sealed");
      return null;
    },
    ui_activity: () => null,
    request_list_pending: () => {
      open();
      return fixtureRequests();
    },
    lease_list: () => {
      open();
      return fixtureLeases();
    },
    agent_list: () => {
      open();
      return fixtureAgents();
    },
    item_list: (args) => {
      open();
      return filterItems(fixtureItems(), (args as { filter?: ItemFilterView_Deserialize } | undefined)?.filter);
    },
    workspace_list: () => {
      open();
      return fixtureWorkspaces();
    },
    settings_get: () => {
      open();
      return { values: fixtureSettings() };
    },
    network_status: () => {
      open();
      return fixtureNetwork();
    },
    clipboard_copy_once: () => null,
    file_pick_open: () => null,
    audit_verify: () => {
      open();
      return { ok: true, count: 0, first_seq: 0, last_seq: 0, broken_seq: null, break_kind: null };
    },
  };
  const handlers = { ...base, ...options.handlers };

  mockIPC(
    async (cmd, payload) => {
      const handler = handlers[cmd];
      if (!handler) throw mockError("unavailable", `the dev mock has no handler for ${cmd}`);
      return handler(payload as MockArgs, ctl);
    },
    { shouldMockEvents: true },
  );
  return ctl;
}
