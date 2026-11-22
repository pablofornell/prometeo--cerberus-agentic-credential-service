// Typed IPC layer over the generated bindings (`src/bindings.ts`, do not edit it).
//
// Every command in `commands` returns `{ status, data | error }`. `ipc` has the same functions, but they
// return the data and throw an `IpcFailure` with a typed `UiError` on any failure. Screens use `ipc`
// (inside TanStack Query hooks) and never call `invoke` themselves.
import { commands, type IpcError_Serialize } from "../bindings";

/** Error codes that the UI reacts to. The backend may send other codes (ADR-0021); they stay plain strings. */
export type KnownErrorCode =
  | "vault_locked"
  | "no_vault"
  | "not_found"
  | "forbidden"
  | "role_not_allowed"
  | "bad_credentials"
  | "too_many_failures"
  | "validation_failed"
  | "conflict"
  | "vault_corrupt"
  | "internal"
  | "window_not_allowed"
  | "invalid_request"
  | "unavailable"
  | "stranded_restore"
  | "ipc_unreachable"
  // Remote mode (ADR-0034): the desktop is a client of one cerberusd.
  | "remote_unsupported"
  | "remote_unreachable"
  | "remote_pin_mismatch"
  | "remote_protocol_mismatch"
  | "admin_session_required"
  | "admin_cert_required"
  | "invalid_bundle"
  // First-time setup of a server (DEC-SRV-3).
  | "unauthenticated"
  | "setup_wrong_server"
  | "setup_unconfirmed";

export type ErrorCode = KnownErrorCode | (string & {});

export interface FieldProblem {
  field: string;
  problem: string;
}

/** The one error shape the UI works with. It never holds a secret: the backend text is fixed English. */
export interface UiError {
  code: ErrorCode;
  /** Short English text from the backend. */
  message: string;
  /** Snake case name of the command that failed, for the mono code line. */
  command: string;
  /** Seconds to wait (unlock back-off, rate limits). */
  retryAfterSeconds: number | null;
  /** Field problems of a `validation_failed` error. */
  fields: FieldProblem[];
}

export class IpcFailure extends Error {
  readonly error: UiError;

  constructor(error: UiError) {
    super(`${error.command}: ${error.code}`);
    this.name = "IpcFailure";
    this.error = error;
  }

  get code(): ErrorCode {
    return this.error.code;
  }
}

export const isIpcFailure = (value: unknown): value is IpcFailure => value instanceof IpcFailure;

/** True when the vault is locked or gone, so the guard must route to the unlock or create screen. */
export const isLockError = (error: unknown): boolean =>
  isIpcFailure(error) && (error.code === "vault_locked" || error.code === "no_vault");

/** True for errors that a second try cannot fix. Query retry uses it. */
export const isFinalError = (error: unknown): boolean =>
  isIpcFailure(error) &&
  error.code !== "internal" &&
  error.code !== "ipc_unreachable" &&
  error.code !== "unavailable" &&
  error.code !== "remote_unreachable";

const snake = (name: string): string => name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

/** Maps the Rust `IpcError` (or anything thrown by the transport) to a `UiError`. */
export function toUiError(command: string, raw: unknown): UiError {
  if (isRecord(raw) && typeof raw.code === "string") {
    const wire = raw as Partial<IpcError_Serialize>;
    return {
      code: wire.code ?? "internal",
      message: typeof wire.message === "string" ? wire.message : "",
      command,
      retryAfterSeconds: typeof wire.retry_after_seconds === "number" ? wire.retry_after_seconds : null,
      fields: Array.isArray(wire.fields) ? wire.fields.map((f) => ({ field: f.field, problem: f.problem })) : [],
    };
  }
  return {
    code: "ipc_unreachable",
    message: "The desktop shell did not answer.",
    command,
    retryAfterSeconds: null,
    fields: [],
  };
}

type Commands = typeof commands;

type Unwrapped<F> = F extends (...args: infer A) => Promise<infer R>
  ? R extends { status: "ok"; data: infer D }
    ? (...args: A) => Promise<D>
    : never
  : never;

/** Same names and arguments as the generated `commands`, but they resolve to the data and throw `IpcFailure`. */
export type Ipc = { [K in keyof Commands]: Unwrapped<Commands[K]> };

async function run(
  name: string,
  fn: (...args: never[]) => Promise<{ status: "ok"; data: unknown } | { status: "error"; error: unknown }>,
  args: never[],
): Promise<unknown> {
  const command = snake(name);
  let result;
  try {
    result = await fn(...args);
  } catch (raw) {
    throw new IpcFailure(toUiError(command, raw));
  }
  if (result.status === "error") {
    throw new IpcFailure(toUiError(command, result.error));
  }
  return result.data;
}

export const ipc = Object.fromEntries(
  Object.entries(commands).map(([name, fn]) => [
    name,
    (...args: never[]) => run(name, fn as Parameters<typeof run>[1], args),
  ]),
) as unknown as Ipc;
