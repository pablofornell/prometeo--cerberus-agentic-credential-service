import { ipc } from "../../ipc/client";
import { useIpcQuery } from "../../ipc/queries";

export const simKey = (agentId: string) => ["policy", "simulate", agentId] as const;

export const useSimulation = (agentId: string) => useIpcQuery(simKey(agentId), () => ipc.policySimulate(agentId));

/** Items with their environment, to label simulator rows. A failure only drops the env column. */
export const useItemEnvs = () => useIpcQuery(["items", "policy-envs"], () => ipc.itemList({}), { retry: false });
