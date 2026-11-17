import type { OperatorRole } from "../bindings";
import { useOperators, useVaultStatus } from "../ipc/queries";
import { autolockStore } from "./live";
import { useNow } from "./time";

const RANK: Record<OperatorRole, number> = { viewer: 0, operator: 1, owner: 2 };

/** Role of the open session, or `null` when the vault is not open. */
export function useRole(): OperatorRole | null {
  return useVaultStatus().data?.role ?? null;
}

/** True when the session role is at least `needed`. Use it to hide or disable actions (the backend still checks). */
export function useCan(needed: OperatorRole): boolean {
  const role = useRole();
  return role !== null && RANK[role] >= RANK[needed];
}

/** Label of the operator who unlocked the vault. */
export function useSessionLabel(): string | null {
  const status = useVaultStatus();
  const operators = useOperators();
  const id = status.data?.operator;
  if (!id) return null;
  return operators.data?.find((o) => o.id === id)?.label ?? null;
}

/**
 * Seconds to the idle lock. It runs between `autolock-tick` events and starts from `idle_seconds_left`
 * of `vault_status` before the first tick. `null` when auto-lock is off or the vault is not open.
 */
export function useAutolockSeconds(): number | null {
  const sample = autolockStore.use();
  const status = useVaultStatus();
  const now = useNow(1000, status.data?.state === "unlocked");
  if (status.data?.state !== "unlocked") return null;
  if (sample) return Math.max(0, sample.seconds - Math.floor((now - sample.at) / 1000));
  const left = status.data.idle_seconds_left;
  if (left == null) return null;
  return Math.max(0, left - Math.floor((now - status.dataUpdatedAt) / 1000));
}
