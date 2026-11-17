import {
  useQuery,
  type QueryKey,
  type UseQueryOptions,
  type UseQueryResult,
} from "@tanstack/react-query";
import { ipc, type IpcFailure } from "./client";
import { qk } from "./keys";

declare module "@tanstack/react-query" {
  interface Register {
    defaultError: IpcFailure;
  }
}

/** `useQuery` with the typed error of the IPC layer. */
export function useIpcQuery<T>(
  key: QueryKey,
  fn: () => Promise<T>,
  options?: Omit<UseQueryOptions<T, IpcFailure>, "queryKey" | "queryFn">,
): UseQueryResult<T, IpcFailure> {
  return useQuery<T, IpcFailure>({ queryKey: key, queryFn: fn, ...options });
}

/** The state of the vault. The route guard reads it first. Events keep it fresh. */
export const useVaultStatus = () => useIpcQuery(qk.vault.status(), () => ipc.vaultStatus());

/** Operators with plain labels. Works while the vault is sealed (DEC-006). */
export const useOperators = () => useIpcQuery(qk.vault.operators(), () => ipc.vaultListOperators());

/** Requests that wait for a person. */
export const usePendingRequests = (enabled = true) =>
  useIpcQuery(qk.requests.pending(), () => ipc.requestListPending(), { enabled });

export const useSettings = (enabled = true) =>
  useIpcQuery(qk.settings(), () => ipc.settingsGet(), { enabled });
