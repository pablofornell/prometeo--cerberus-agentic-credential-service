import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import type { AuditEntryView_Serialize } from "../../bindings";
import { ipc } from "../../ipc/client";
import { useIpcQuery } from "../../ipc/queries";
import { qk } from "../../ipc/keys";
import { useRemoteUnsupported } from "../../state/backendMode";

export type Range = "day" | "week" | "month" | "all";
export const RANGE_SECONDS: Record<Range, number | null> = { day: 86_400, week: 604_800, month: 2_592_000, all: null };
export const PAGE_SIZE = 100;

/** `all` sends no outcome filter. */
export type Outcome = "all" | "ok" | "failed";

export interface AuditFilter {
  range: Range;
  eventType: string;
  agentId: string;
  outcome: Outcome;
  /** Free text, trimmed, 200 characters at most. Empty means no text filter. */
  text: string;
}

export const NO_FILTER: AuditFilter = { range: "all", eventType: "", agentId: "", outcome: "all", text: "" };

export const auditKeys = {
  verify: () => ["audit", "verify"] as const,
  list: (f: AuditFilter) => ["audit", "query", f] as const,
  items: () => [...qk.items.all(), "list"] as const,
};

/** The same key as the dashboard health row, so both screens show one answer. */
export function useChain() {
  const localOnly = useRemoteUnsupported("audit_verify");
  return useQuery({
    enabled: !localOnly,
    queryKey: auditKeys.verify(),
    queryFn: () => ipc.auditVerify(),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

/** Pages of events, newest first. The cursor is the lowest `seq` of the last page. */
export function useEvents(filter: AuditFilter) {
  return useInfiniteQuery({
    queryKey: auditKeys.list(filter),
    initialPageParam: null as number | null,
    queryFn: async ({ pageParam }): Promise<AuditEntryView_Serialize[]> => {
      const seconds = RANGE_SECONDS[filter.range];
      const rows = await ipc.auditQuery({
        from: seconds === null ? null : new Date(Date.now() - seconds * 1000).toISOString(),
        event_type: filter.eventType || null,
        agent_id: filter.agentId || null,
        outcome: filter.outcome === "all" ? null : filter.outcome,
        text: filter.text.trim() === "" ? null : filter.text.trim().slice(0, 200),
        before_seq: pageParam,
        limit: PAGE_SIZE,
      });
      return [...rows].sort((a, b) => b.seq - a.seq);
    },
    getNextPageParam: (last) => (last.length >= PAGE_SIZE ? (last[last.length - 1]?.seq ?? null) : null),
    refetchOnWindowFocus: false,
  });
}

export const useAuditAgents = () => useIpcQuery(qk.agents(), () => ipc.agentList());
export const useAuditItems = () => useIpcQuery(auditKeys.items(), () => ipc.itemList({}));
