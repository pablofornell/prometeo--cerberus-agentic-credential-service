import { ipc } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useIpcQuery } from "../../ipc/queries";

export const grantsKey = (agentId: string) => ["grants", agentId] as const;
export const WORKSPACES_KEY = ["workspaces"] as const;

export const useAgents = () => useIpcQuery(qk.agents(), () => ipc.agentList());
export const useWorkspaces = () => useIpcQuery(WORKSPACES_KEY, () => ipc.workspaceList());
export const useAgentGrants = (agentId: string | null) =>
  useIpcQuery(grantsKey(agentId ?? ""), () => ipc.grantList(agentId), { enabled: agentId !== null });
export const useSnippets = (agentId: string) =>
  useIpcQuery(["agent-snippets", agentId], () => ipc.agentSnippets(agentId));
