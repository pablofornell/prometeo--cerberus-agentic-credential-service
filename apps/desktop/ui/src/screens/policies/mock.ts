// Dev mock of the grant commands. The simulator runs a small version of the policy rules on the fake items.
// Switches: `?mock_policies=empty|error|slow`. Role `viewer` and `operator` cannot set `allow_prod_auto`.
import type { GrantInputView_Deserialize, GrantView_Serialize, SimulationRow_Serialize } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { devFlag, fixtureItems, fixtureWorkspaces, secondsFromNow, sleep } from "../../ipc/mock/fixtures";

const now = () => secondsFromNow(0);

function seed(): GrantView_Serialize[] {
  const empty = { time_window: null, max_reads_per_hour: null, expires_at: null, reason_required: false };
  const base = { allow_prod_auto: false, created_at: now(), updated_at: now() };
  const sel = { workspace_ids: [], environments: [], categories: [], tags: [], kinds: [], role_labels: [], item_ids: [] };
  return [
    { ...base, id: "grt_1", agent_id: "agent-qa", selector: { ...sel, workspace_ids: ["ws-shop"], environments: ["staging"] }, permissions: ["read"], mode: "auto", conditions: empty },
    { ...base, id: "grt_2", agent_id: "agent-qa", selector: { ...sel, workspace_ids: ["ws-shop"], environments: ["prod"], categories: ["Web login"] }, permissions: ["read"], mode: "ask_always", conditions: { ...empty, reason_required: true } },
    { ...base, id: "grt_3", agent_id: "agent-qa", selector: { ...sel, workspace_ids: ["ws-shop"] }, permissions: ["create_session"], mode: "auto", conditions: empty },
    { ...base, id: "grt_4", agent_id: "agent-qa", selector: { ...sel, workspace_ids: ["ws-billing"], environments: ["prod"] }, permissions: ["read"], mode: "deny", conditions: empty },
  ];
}

/** A fresh set of handlers with its own state. Tests call this for each test. */
export function policyHandlers(role: () => string = () => "owner"): MockHandlers {
  let grants = seed();
  let counter = 0;
  const items = fixtureItems();
  const workspaces = fixtureWorkspaces();
  const simulate = (agentId: string): SimulationRow_Serialize[] => {
    const mine = grants.filter((g) => g.agent_id === agentId);
    const rows: SimulationRow_Serialize[] = [];
    for (const it of items) {
      const ws = workspaces.find((w) => w.slug === it.workspace)?.id ?? "";
      const matching = mine.filter((g) => {
        const s = g.selector;
        return (
          (s.workspace_ids.length === 0 || s.workspace_ids.includes(ws)) &&
          (s.environments.length === 0 || s.environments.includes(it.environment)) &&
          (s.categories.length === 0 || s.categories.includes(it.category)) &&
          (s.kinds.length === 0 || s.kinds.includes(it.kind))
        );
      });
      const perms = new Set(matching.flatMap((g) => g.permissions));
      perms.add("read");
      for (const permission of perms) {
        const grant = matching.find((g) => g.mode === "deny" && g.permissions.includes(permission)) ?? matching.find((g) => g.permissions.includes(permission));
        const decision = !grant
          ? { outcome: "no_grant", mode: null, grant_id: null, retry_after_seconds: null }
          : grant.mode === "deny"
            ? { outcome: "deny", mode: null, grant_id: grant.id, retry_after_seconds: null }
            : { outcome: "allow", mode: it.environment === "prod" && !grant.allow_prod_auto ? ("ask_always" as const) : grant.mode, grant_id: grant.id, retry_after_seconds: null };
        rows.push({ item_id: it.id, title: it.title, permission, decision });
      }
    }
    return rows;
  };
  return {
    grant_list: async (args) => {
      const flag = devFlag("mock_policies");
      if (flag === "slow") await sleep(60_000);
      if (flag === "error") throw mockError("internal", "the grant list did not load");
      const id = (args as { agentId: string | null }).agentId;
      return flag === "empty" ? [] : grants.filter((g) => id === null || g.agent_id === id);
    },
    grant_put: (args) => {
      const input = (args as { input: GrantInputView_Deserialize }).input;
      if (input.allow_prod_auto && role() !== "owner") throw mockError("forbidden", "only the owner can allow prod reads without asking");
      counter += 1;
      const grant: GrantView_Serialize = {
        id: input.id ?? `grt_new${counter}`,
        agent_id: input.agent_id,
        selector: input.selector,
        permissions: input.permissions,
        mode: input.mode,
        conditions: {
          time_window: input.conditions.time_window ?? null,
          max_reads_per_hour: input.conditions.max_reads_per_hour ?? null,
          expires_at: input.conditions.expires_at ?? null,
          reason_required: input.conditions.reason_required,
        },
        allow_prod_auto: input.allow_prod_auto,
        created_at: now(),
        updated_at: now(),
      };
      grants = input.id ? grants.map((g) => (g.id === input.id ? grant : g)) : [...grants, grant];
      return grant;
    },
    grant_delete: (args) => {
      grants = grants.filter((g) => g.id !== (args as { grant: string }).grant);
      return null;
    },
    policy_simulate: (args) => simulate((args as { agentId: string }).agentId),
  };
}

export const handlers: MockHandlers = policyHandlers();
