import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { AgentActivity, AuditEntryView_Serialize } from "../../bindings";
import { ipc } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useIpcQuery, usePendingRequests } from "../../ipc/queries";
import { useRemoteUnsupported } from "../../state/backendMode";
import { agentFeedStore, FEED_LIMIT } from "../../state/live";

export const dashKeys = {
  items: () => [...qk.items.all(), "list"] as const,
  leases: () => [...qk.leases.all(), "list"] as const,
  network: () => ["network", "status"] as const,
  verify: () => ["audit", "verify"] as const,
  recent: () => ["audit", "recent-agent-events"] as const,
};

/** All reads of the dashboard. Each part has its own state, so one failure does not blank the page. */
export function useDashboardData() {
  const agents = useIpcQuery(qk.agents(), () => ipc.agentList());
  const items = useIpcQuery(dashKeys.items(), () => ipc.itemList({}));
  const leases = useIpcQuery(dashKeys.leases(), () => ipc.leaseList());
  const requests = usePendingRequests();
  // A remote server has no local listener to show (network_status is local only, DEC-RM-11).
  const localOnly = useRemoteUnsupported("network_status");
  const network = useIpcQuery(dashKeys.network(), () => ipc.networkStatus(), { enabled: !localOnly });
  return { agents, items, leases, requests, network, localOnly };
}

/** The chain check. It runs when the dashboard opens and again on "Verify". */
export function useChainReport() {
  const localOnly = useRemoteUnsupported("audit_verify");
  return useQuery({
    queryKey: dashKeys.verify(),
    queryFn: () => ipc.auditVerify(),
    enabled: !localOnly,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

const toActivity = (e: AuditEntryView_Serialize): AgentActivity | null =>
  e.actor_kind === "agent" && e.actor_id
    ? { agent_id: e.actor_id, event_type: e.event_type, item_id: e.target_kind === "item" ? e.target_id : null, at: e.occurred_at }
    : null;

const keyOf = (a: AgentActivity) => `${a.at}|${a.agent_id}|${a.event_type}|${a.item_id ?? ""}`;

/**
 * Seeds the live feed with the last agent events of the audit log, so the feed is not empty on open.
 * Events that came live stay on top. Metadata only (I-19).
 */
export function useSeedFeed(): void {
  const queryClient = useQueryClient();
  const recent = useQuery({
    queryKey: dashKeys.recent(),
    queryFn: () => ipc.auditQuery({ limit: 40 }),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    if (!recent.data) return;
    const seeded = recent.data.map(toActivity).filter((a): a is AgentActivity => a !== null);
    agentFeedStore.set((live) => {
      const seen = new Set(live.map(keyOf));
      return [...live, ...seeded.filter((a) => !seen.has(keyOf(a)))].slice(0, FEED_LIMIT);
    });
  }, [recent.data, queryClient]);
}
