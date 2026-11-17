import { useQueryClient } from "@tanstack/react-query";
import { events } from "../../bindings";
import { ipc } from "../../ipc/client";
import { useTauriEvent } from "../../ipc/events";
import { qk } from "../../ipc/keys";
import { useIpcQuery } from "../../ipc/queries";

// All keys sit under ["items"] or ["workspaces"], so a vault lock removes them (DEC-T16-3).
export const vaultKeys = {
  list: () => [...qk.items.all(), "list"] as const,
  search: (q: string) => qk.items.search(q),
  detail: (id: string) => [...qk.items.all(), "detail", id] as const,
  versions: (id: string) => [...qk.items.all(), "versions", id] as const,
  workspaces: () => ["workspaces"] as const,
};

/** Every item, metadata only. Filters and counts run in the browser on this list. */
export const useAllItems = () => useIpcQuery(vaultKeys.list(), () => ipc.itemList({}));

/** The backend search (its index knows synonyms). Runs only while the search box has text. */
export const useSearchIds = (q: string) =>
  useIpcQuery(vaultKeys.search(q), () => ipc.itemList({ q }), { enabled: q.trim().length > 0 });

export const useWorkspaces = () => useIpcQuery(vaultKeys.workspaces(), () => ipc.workspaceList());

export const useItemDetail = (id: string | null) =>
  useIpcQuery(vaultKeys.detail(id ?? ""), () => ipc.itemGet(id ?? ""), { enabled: id !== null });

export const useVersions = (id: string, enabled: boolean) =>
  useIpcQuery(vaultKeys.versions(id), () => ipc.itemVersions(id), { enabled });

/** Agents' names for the "exposed to" line. */
export const useAgentNames = () => useIpcQuery(qk.agents(), () => ipc.agentList());

/** Exposure changes with leases: refresh the details of the open item. */
export function useExposureRefresh(): void {
  const queryClient = useQueryClient();
  useTauriEvent(events.leaseChanged, () => {
    void queryClient.invalidateQueries({ queryKey: [...qk.items.all(), "detail"] });
  });
}

/** After a save or delete in any screen: reload lists and counts. */
export function invalidateItems(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: qk.items.all() });
  void queryClient.invalidateQueries({ queryKey: vaultKeys.workspaces() });
}
