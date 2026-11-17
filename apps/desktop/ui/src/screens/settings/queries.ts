import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { SettingsView, Value } from "../../bindings";
import { ipc, type IpcFailure } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useIpcQuery } from "../../ipc/queries";

export const settingsKeys = {
  network: () => ["settings", "network"] as const,
};

/** The listen address, port, pins and certificate dates. Any role may read it. */
export const useNetwork = () => useIpcQuery(settingsKeys.network(), () => ipc.networkStatus());

/** Writes one setting and puts the answer (all settings) in the cache. */
export function useSetSetting(onError: (error: IpcFailure) => void) {
  const queryClient = useQueryClient();
  return useMutation<SettingsView, IpcFailure, { key: string; value: Value }>({
    mutationFn: ({ key, value }) => ipc.settingsSet(key, value),
    onSuccess: (view) => queryClient.setQueryData(qk.settings(), view),
    onError,
  });
}

export const num = (values: Record<string, Value>, key: string, fallback: number | null): number | null => {
  const v = values[key];
  if (v === null) return null;
  return typeof v === "number" ? v : fallback;
};

export const flag = (values: Record<string, Value>, key: string, fallback: boolean): boolean => {
  const v = values[key];
  return typeof v === "boolean" ? v : fallback;
};
