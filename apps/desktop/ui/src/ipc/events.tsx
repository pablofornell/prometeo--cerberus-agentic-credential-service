// Subscriptions to the backend events (tauri-specta `events`). `EventBridge` is mounted once per window.
// It writes to the live stores and invalidates queries. Payloads hold IDs and metadata only.
import { useEffect, useRef } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { events } from "../bindings";
import type { VaultState } from "../bindings";
import { agentFeedStore, alertsStore, autolockStore, FEED_LIMIT, resetLiveState, vaultStateStore } from "../state/live";
import { qk } from "./keys";

type EventSource<T> = { listen: (cb: (event: { payload: T }) => void) => Promise<() => void> };

/** Listens to one event for the life of the component. Safe if the component unmounts before `listen` resolves. */
export function useTauriEvent<T>(source: EventSource<T>, handler: (payload: T) => void): void {
  const latest = useRef(handler);
  useEffect(() => {
    latest.current = handler;
  });
  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    source
      .listen((event) => latest.current(event.payload))
      .then((fn) => {
        if (active) unlisten = fn;
        else fn();
      })
      .catch(() => {
        // No Tauri runtime (a plain browser). The UI then relies on queries only.
      });
    return () => {
      active = false;
      unlisten?.();
    };
  }, [source]);
}

/** What leaves the webview when the vault is no longer open: cached data and live values (I-16). */
export function dropVaultData(queryClient: QueryClient): void {
  queryClient.removeQueries({
    predicate: (q) => q.queryKey[0] !== "vault",
  });
  resetLiveState();
}

export function applyVaultState(queryClient: QueryClient, state: VaultState): void {
  vaultStateStore.set(state);
  if (state !== "unlocked") dropVaultData(queryClient);
  void queryClient.invalidateQueries({ queryKey: qk.vault.status() });
}

export function EventBridge() {
  const queryClient = useQueryClient();

  useTauriEvent(events.vaultStateChanged, ({ state }) => applyVaultState(queryClient, state));
  useTauriEvent(events.autolockTick, ({ seconds_left }) =>
    autolockStore.set({ seconds: seconds_left, at: Date.now() }),
  );
  useTauriEvent(events.pendingCountChanged, () => {
    void queryClient.invalidateQueries({ queryKey: qk.requests.all() });
  });
  useTauriEvent(events.accessRequestCreated, () => {
    void queryClient.invalidateQueries({ queryKey: qk.requests.all() });
  });
  useTauriEvent(events.accessRequestResolved, () => {
    void queryClient.invalidateQueries({ queryKey: qk.requests.all() });
  });
  useTauriEvent(events.leaseChanged, () => {
    void queryClient.invalidateQueries({ queryKey: qk.leases.all() });
  });
  useTauriEvent(events.agentActivity, (activity) => {
    agentFeedStore.set((prev) => [activity, ...prev].slice(0, FEED_LIMIT));
    void queryClient.invalidateQueries({ queryKey: qk.agents() });
  });
  useTauriEvent(events.massReadAlert, (alert) =>
    alertsStore.set((prev) => ({ ...prev, massRead: [alert, ...prev.massRead] })),
  );
  useTauriEvent(events.integrityAlert, (alert) =>
    alertsStore.set((prev) => ({ ...prev, integrity: [alert, ...prev.integrity] })),
  );
  useTauriEvent(events.headerMismatch, () => alertsStore.set((prev) => ({ ...prev, headerMismatch: true })));

  return null;
}
