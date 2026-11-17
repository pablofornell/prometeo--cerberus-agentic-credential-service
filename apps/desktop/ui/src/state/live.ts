// Live values that backend events write. Components read them with `.use()`.
import type { AgentActivity, IntegrityAlert, MassReadAlert, VaultState } from "../bindings";
import { createStore } from "./store";

/** Last vault state seen from `vault_status` or `vault-state-changed`. `unknown` until the first answer. */
export const vaultStateStore = createStore<VaultState | "unknown">("unknown");

/** Seconds to the auto-lock, with the time we got the value, so the countdown can run between ticks. */
export interface AutolockSample {
  seconds: number;
  at: number;
}
export const autolockStore = createStore<AutolockSample | null>(null);

export const FEED_LIMIT = 50;
/** Newest first. Metadata only: agent ID, event type, item ID, time (I-19). */
export const agentFeedStore = createStore<AgentActivity[]>([]);

export interface AlertState {
  massRead: MassReadAlert[];
  integrity: IntegrityAlert[];
  headerMismatch: boolean;
}
export const alertsStore = createStore<AlertState>({ massRead: [], integrity: [], headerMismatch: false });

/** Forget everything the webview holds about the vault. Runs when the vault locks (ADR-0010). */
export function resetLiveState(): void {
  autolockStore.set(null);
  agentFeedStore.set([]);
  alertsStore.set({ massRead: [], integrity: [], headerMismatch: false });
}
