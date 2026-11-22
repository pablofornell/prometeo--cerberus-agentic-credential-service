// A fake backend for the browser and for tests. It answers the IPC commands with fake data only.
// `installMock` uses the official `mockIPC` of @tauri-apps/api, so the real `commands` and `events` run on top of it.
import { emit } from "@tauri-apps/api/event";
import { mockIPC } from "@tauri-apps/api/mocks";
import type { IpcError_Serialize, ItemFilterView_Deserialize, LockReasonView, OperatorRole, RemoteProfileView, RemoteStatusView_Serialize, VaultState, VaultStatusView_Serialize } from "../../bindings";
import {
  FIXTURE_KDF,
  filterItems,
  fixtureAgents,
  fixtureItems,
  fixtureLeases,
  fixtureNetwork,
  fixtureRequests,
  fixtureSettings,
  fixtureWorkspaces,
  MOCK_DESKTOP_COMMANDS,
  MOCK_OPERATORS,
  MOCK_PROFILE,
  MOCK_REMOTE_COMMANDS,
  MOCK_SETUP_RECOVERY_KEY,
  remoteStatusOf,
} from "./fixtures";

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
  /** Remote mode (ADR-0034): the server as the desktop sees it, or `null` in local mode. `has_session` follows `state`. */
  remote: RemoteStatusView_Serialize | null;
  /** The stored remote profiles (`remote_status`). */
  profiles: RemoteProfileView[];
  /** The last `remote_activate`: the profile the next start uses (`null` = local). The mock "restarts" at once. */
  activated: string | null | undefined;
  /** A staged bundle import (`remote_import_bundle`), stored only by `remote_activate` of its ID. */
  staged: RemoteProfileView | null;
  /** The arguments of every command the mock answered, by command name, in order. For tests. */
  calls: Record<string, unknown[]>;
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
  /** Remote mode: `true` for the sample server, or the fields that differ from it (`reachable: false`, `problem`). */
  remote?: boolean | Partial<RemoteStatusView_Serialize>;
  /** The stored remote profiles. Default: the sample profile in remote mode, none in local mode. */
  profiles?: RemoteProfileView[];
  /** Extra or replacing handlers. Screen folders add theirs in `src/screens/<id>/mock.ts`. */
  handlers?: MockHandlers;
}

/** Wrong tries in a row before the backend makes the person wait (`FREE_UNLOCK_FAILURES`). */
export const FREE_UNLOCK_FAILURES = 5;

const SETUP_PREFIX = "cerberus-setup:1:";
const SETUP_URL = "https://vault.example.test:7373";

/** What the mock server of a setup code is: the end of the code names the scenario (see `MOCK_SETUP_CODE`). */
function setupServer(code: string, url: string | null): { url: string; scenario: string } {
  const text = code.trim();
  if (!text.startsWith(SETUP_PREFIX) || text.length === SETUP_PREFIX.length) {
    throw mockError("validation_failed", "validation failed", { fields: [{ field: "code", problem: "is not a Cerberus setup code" }] });
  }
  const chosen = url?.trim();
  if (chosen && !/^https:\/\/[^/\s]+$/.test(chosen)) {
    throw mockError("validation_failed", "validation failed", { fields: [{ field: "url", problem: "must look like https://host:port" }] });
  }
  return { url: chosen || SETUP_URL, scenario: text.slice(SETUP_PREFIX.length) };
}

export function installMock(options: MockOptions = {}): MockController {
  const ctl: MockController = {
    state: options.state ?? "unlocked",
    role: options.role ?? "owner",
    idleSecondsLeft: 1661,
    lockReason: options.lockReason ?? null,
    failedUnlocks: 0,
    retryUntil: null,
    stranded: options.stranded ?? [],
    remote: options.remote ? remoteStatusOf(MOCK_PROFILE, options.remote === true ? {} : options.remote) : null,
    profiles: options.profiles ?? (options.remote ? [{ ...MOCK_PROFILE, active: true }] : []),
    activated: undefined,
    staged: null,
    calls: {},
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
    remote: ctl.remote ? { ...ctl.remote, has_session: ctl.state === "unlocked", server_state: ctl.state === "unlocked" ? "unlocked" : ctl.remote.server_state } : null,
  });

  /** In remote mode the server must answer: an unreachable mock server fails every call that goes to it. */
  const reach = (): void => {
    if (ctl.remote && !ctl.remote.reachable) throw mockError(ctl.remote.problem ?? "remote_unreachable", "cannot reach the server");
  };

  const open = (): void => {
    if (ctl.state !== "unlocked") throw mockError("vault_locked", "the vault is locked");
  };

  /** The result of the last `remote_setup` that `remote_setup_finish` did not drop. */
  let held: { profile: RemoteProfileView; stored: boolean } | null = null;

  // The base answers every command a screen reads, from the shared fixtures. Screen mocks replace the ones they own.
  const base: MockHandlers = {
    vault_status: () => status(),
    vault_list_operators: () => {
      reach();
      return MOCK_OPERATORS;
    },
    remote_status: (_args, c) => ({
      mode: c.remote ? "remote" : "local",
      active: c.remote?.profile_id ?? null,
      profiles: c.profiles.map((p) => ({ ...p, active: p.id === c.remote?.profile_id })),
      remote_commands: [...MOCK_REMOTE_COMMANDS],
    }),
    remote_import_bundle: (args, c) => {
      const path = String((args as { path?: string } | undefined)?.path ?? "");
      if (!path.endsWith(".cerberus-admin")) throw mockError("invalid_bundle", "the file is not a valid Cerberus admin bundle: not bundle JSON");
      // Staged only: a stored profile of the same enrolment changes at `remote_activate`.
      c.staged = { ...MOCK_PROFILE, active: false };
      return c.staged;
    },
    remote_setup_check: async (args) => {
      const { code, url } = (args as { code?: string; url?: string | null } | undefined) ?? {};
      await new Promise((r) => setTimeout(r, 250));
      const server = setupServer(String(code ?? ""), url ?? null);
      if (server.scenario === "down") throw mockError("remote_unreachable", "cannot reach the server");
      if (server.scenario === "wrong") throw mockError("setup_wrong_server", "this is not the server of the setup code");
      if (server.scenario === "exists") throw mockError("conflict", "this server already has a vault");
      return { url: server.url, state: server.scenario === "locked" ? "locked_out" : "pending", version: "0.4.0" };
    },
    remote_setup: async (args, c) => {
      const a = (args as { code?: string; ownerLabel?: string; passphrase?: string; deviceLabel?: string | null; url?: string | null } | undefined) ?? {};
      const server = setupServer(String(a.code ?? ""), a.url ?? null);
      await new Promise((r) => setTimeout(r, 400));
      // The scenario `toomany` asks for a wait of two seconds on the first try, as a server that counted five wrong codes.
      if (server.scenario === "toomany" && (c.calls.remote_setup?.length ?? 0) === 1) {
        throw mockError("too_many_failures", "wait before the next try", { retry_after_seconds: 2 });
      }
      if (server.scenario === "badtoken") throw mockError("unauthenticated", "the setup token is not valid");
      if (server.scenario === "busy") throw mockError("conflict", "a setup is running");
      if (server.scenario === "lost") throw mockError("setup_unconfirmed", "the answer of the server did not arrive; the vault may exist");
      if ((a.passphrase ?? "").length < 12) {
        throw mockError("validation_failed", "validation failed", { fields: [{ field: "passphrase", problem: "must have at least 12 characters" }] });
      }
      if ((a.ownerLabel ?? "").toLowerCase() === "fail") throw mockError("internal", "internal error");
      const profile = { ...MOCK_PROFILE, id: "0196d7a0-1c2e-7c3a-9f00-00000000b001", label: a.deviceLabel || "desktop", url: server.url, active: false };
      // Like the backend: the key and the profile are held from here on, and a profile that cannot be stored still answers.
      held = { profile, stored: false };
      if (server.scenario === "nostore") {
        return { profile: null, store_error: mockError("internal", "internal error"), recovery_key: MOCK_SETUP_RECOVERY_KEY };
      }
      held.stored = true;
      c.profiles = [...c.profiles.filter((p) => p.id !== profile.id), profile];
      return { profile, store_error: null, recovery_key: MOCK_SETUP_RECOVERY_KEY };
    },
    remote_setup_save: (_args, c) => {
      if (!held) throw mockError("not_found", "there is no server setup to save");
      // The scenario `nostore` fails the first save, as a disk that is still full.
      if (!held.stored && (c.calls.remote_setup_save?.length ?? 0) === 1) throw mockError("internal", "internal error");
      held.stored = true;
      const profile = held.profile;
      c.profiles = [...c.profiles.filter((p) => p.id !== profile.id), profile];
      return profile;
    },
    remote_setup_copy_key: () => {
      if (!held) throw mockError("not_found", "there is no such value to copy");
      return null;
    },
    remote_setup_finish: () => {
      held = null;
      return null;
    },
    remote_discard_import: (_args, c) => {
      c.staged = null;
      return null;
    },
    remote_activate: async (args, c) => {
      const { profile: id = null, lockLocal = false } = (args as { profile?: string | null; lockLocal?: boolean } | undefined) ?? {};
      const staged = c.staged && c.staged.id === id ? c.staged : null;
      const profile = id === null ? null : (staged ?? c.profiles.find((p) => p.id === id));
      if (profile === undefined) throw mockError("not_found", "no remote profile with this ID");
      if (!c.remote && c.state === "unlocked" && !lockLocal) throw mockError("conflict", "lock the local vault before you switch to a remote server");
      if (staged) {
        c.profiles = [...c.profiles.filter((p) => p.id !== staged.id), staged];
        c.staged = null;
      }
      // The real app restarts here. The mock goes straight to the new backend, sealed.
      c.activated = id;
      c.remote = profile ? remoteStatusOf(profile) : null;
      c.lockReason = null;
      await c.setState("sealed");
      return null;
    },
    remote_disconnect: async (_args, c) => {
      if (!c.remote) throw mockError("unavailable", "not connected to a remote server");
      await c.setState("sealed");
      return null;
    },
    remote_forget: (args, c) => {
      const id = String((args as { profile?: string } | undefined)?.profile ?? "");
      if (c.remote?.profile_id === id) throw mockError("conflict", "this profile is in use; switch to another backend first");
      c.profiles = c.profiles.filter((p) => p.id !== id);
      return null;
    },
    vault_unlock: async (_args, c) => {
      c.failedUnlocks = 0;
      c.retryUntil = null;
      await c.setState("unlocked");
      return { operator_id: "op-ana", role: "owner", unlocked_at: new Date().toISOString(), via_recovery: false };
    },
    vault_lock: async (_args, c) => {
      if (c.remote) c.remote = { ...c.remote, server_state: "sealed" };
      c.lockReason = "manual";
      await c.setState("sealed");
      return null;
    },
    vault_panic: async (_args, c) => {
      if (c.remote) c.remote = { ...c.remote, server_state: "sealed" };
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
    // The dialog of the bundle import answers with a sample bundle; every other dialog is cancelled.
    file_pick_open: (args) => (((args as { extensions?: string[] } | undefined)?.extensions ?? []).includes("cerberus-admin") ? "/home/demo/build-server.cerberus-admin" : null),
    audit_verify: () => {
      open();
      return { ok: true, count: 0, first_seq: 0, last_seq: 0, broken_seq: null, break_kind: null };
    },
  };
  const handlers = { ...base, ...options.handlers };

  const remoteOnly = new Set<string>([...MOCK_REMOTE_COMMANDS, ...MOCK_DESKTOP_COMMANDS]);
  mockIPC(
    async (cmd, payload) => {
      // Remote mode: the desktop refuses every command off the allowlist before the network (DEC-RM-11).
      if (ctl.remote && !cmd.startsWith("plugin:") && !remoteOnly.has(cmd)) throw mockError("remote_unsupported", "not available for a remote server");
      if (ctl.remote && MOCK_REMOTE_COMMANDS.includes(cmd as (typeof MOCK_REMOTE_COMMANDS)[number]) && cmd !== "vault_status") reach();
      (ctl.calls[cmd] ??= []).push(payload);
      const handler = handlers[cmd];
      if (!handler) throw mockError("unavailable", `the dev mock has no handler for ${cmd}`);
      return handler(payload as MockArgs, ctl);
    },
    { shouldMockEvents: true },
  );
  return ctl;
}
