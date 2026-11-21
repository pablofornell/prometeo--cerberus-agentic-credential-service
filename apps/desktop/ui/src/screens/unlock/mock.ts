// Dev and test backend for the unlock screen. Fake data only.
// Dev rules: the phrase "open sesame phrase" (or the recovery key of the create mock) opens the vault. Any other
// phrase fails; after 5 failures in a row the mock answers with a 30 s wait. A phrase starting with "cost" answers
// with the unsupported unlock cost error. The counters live in the mock controller, so `vault_status` shows them.
import { FREE_UNLOCK_FAILURES, mockError, type MockController, type MockHandlers } from "../../ipc/mock/core";

export const MOCK_PHRASE = "open sesame phrase";
const WAIT_MS = 30_000;

const fail = (ctl: MockController): never => {
  if (ctl.retryUntil !== null && ctl.retryUntil > Date.now()) {
    throw mockError("too_many_failures", "wait before the next try", { retry_after_seconds: Math.ceil((ctl.retryUntil - Date.now()) / 1000) });
  }
  ctl.failedUnlocks += 1;
  if (ctl.failedUnlocks > FREE_UNLOCK_FAILURES) {
    ctl.retryUntil = Date.now() + WAIT_MS;
    throw mockError("too_many_failures", "wait before the next try", { retry_after_seconds: WAIT_MS / 1000 });
  }
  throw mockError("bad_credentials", "that phrase does not open the vault");
};

const opened = async (ctl: MockController): Promise<void> => {
  ctl.failedUnlocks = 0;
  ctl.retryUntil = null;
  await ctl.setState("unlocked");
};

export const handlers: MockHandlers = {
  // Puts the stranded vault back: the status has no old files any more and the vault is sealed (T27-G).
  vault_recover_stranded: async (_args, ctl) => {
    await new Promise((r) => setTimeout(r, 50));
    ctl.stranded = [];
    await ctl.setState("sealed");
    return null;
  },
  vault_unlock: async (args, ctl) => {
    const phrase = String((args as { phrase?: string } | undefined)?.phrase ?? "");
    const operator = String((args as { operatorId?: string } | undefined)?.operatorId ?? "");
    await new Promise((r) => setTimeout(r, 300));
    // A remote enrolment opens sessions for its bound operator only (ADR-0034 point 3.3).
    if (ctl.remote && operator !== ctl.remote.operator_id) throw mockError("forbidden", "this enrolment is bound to another operator");
    if (phrase.startsWith("cost")) throw mockError("unavailable", "the unlock cost is not supported on this device");
    if (phrase !== MOCK_PHRASE) fail(ctl);
    await opened(ctl);
    return { operator_id: "op-ana", role: "owner", unlocked_at: new Date().toISOString(), via_recovery: false };
  },
  vault_unlock_recovery: async (args, ctl) => {
    const key = String((args as { recoveryKey?: string } | undefined)?.recoveryKey ?? "");
    await new Promise((r) => setTimeout(r, 300));
    if (!/^CRK1-/i.test(key)) throw mockError("validation_failed", "not a recovery key", { fields: [{ field: "recovery_key", problem: "is not a valid recovery key" }] });
    if (!key.includes("DEMO")) fail(ctl);
    await opened(ctl);
    return { operator_id: "recovery", role: "owner", unlocked_at: new Date().toISOString(), via_recovery: true };
  },
};
