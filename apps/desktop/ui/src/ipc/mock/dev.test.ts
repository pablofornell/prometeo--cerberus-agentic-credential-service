import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it } from "vitest";
import type {
  AgentView_Serialize,
  AuditEntryView_Serialize,
  GrantView_Serialize,
  ItemSummaryView_Serialize,
  LeaseDetailView_Serialize,
  NetworkView_Serialize,
  AccessRequestView_Serialize,
  VaultStatusView_Serialize,
  WorkspaceView,
} from "../../bindings";
import { installMock, type MockHandlers } from "./core";
import { mergeHandlers, screenSources } from "./dev";

/** What a screen reads in `pnpm dev`: every screen mock merged over the base, so the lists must agree with each other. */
const merged = mergeHandlers(screenSources());
const call = <T>(command: string, args?: Record<string, unknown>): Promise<T> => invoke<T>(command, args);

const ids = (list: readonly { id: string }[]): string[] => list.map((x) => x.id);
const unique = (list: readonly string[]): boolean => new Set(list).size === list.length;

describe("dev mock merge", () => {
  it("answers each command in exactly one screen mock", () => {
    const owners = new Map<string, string[]>();
    for (const [source, handlers] of Object.entries(screenSources())) {
      for (const command of Object.keys(handlers)) owners.set(command, [...(owners.get(command) ?? []), source]);
    }
    const doubled = [...owners].filter(([, sources]) => sources.length > 1);
    expect(doubled).toEqual([]);
    expect(Object.keys(merged).sort()).toEqual([...owners.keys()].sort());
  });

  it("refuses a command with two owners", () => {
    const answer: MockHandlers = { agent_list: () => [] };
    expect(() => mergeHandlers({ first: answer, second: answer })).toThrow(/agent_list/);
  });

  it("has an owner for every list a screen reads", () => {
    for (const command of ["agent_list", "item_list", "workspace_list", "lease_list", "request_list_pending", "grant_list", "settings_get", "network_status", "audit_query", "vault_list_operators"]) {
      expect(Object.keys(merged), command).toContain(command);
    }
  });
});

describe("dev mock data", () => {
  beforeEach(() => {
    installMock({ handlers: merged });
  });

  it("uses unique ids in every list", async () => {
    const [agents, items, workspaces, leases, requests, grants] = await Promise.all([
      call<AgentView_Serialize[]>("agent_list"),
      call<ItemSummaryView_Serialize[]>("item_list", { filter: {} }),
      call<WorkspaceView[]>("workspace_list"),
      call<LeaseDetailView_Serialize[]>("lease_list"),
      call<AccessRequestView_Serialize[]>("request_list_pending"),
      call<GrantView_Serialize[]>("grant_list", { agentId: null }),
    ]);
    for (const list of [ids(agents), ids(items), ids(workspaces), leases.map((l) => l.view.id), ids(requests), ids(grants), agents.flatMap((a) => a.keys.map((k) => k.id))]) {
      expect(list.length).toBeGreaterThan(0);
      expect(unique(list)).toBe(true);
    }
  });

  it("points every lease, request and grant at an agent, item and workspace that exist", async () => {
    const agents = await call<AgentView_Serialize[]>("agent_list");
    const items = await call<ItemSummaryView_Serialize[]>("item_list", { filter: {} });
    const workspaces = await call<WorkspaceView[]>("workspace_list");
    const leases = await call<LeaseDetailView_Serialize[]>("lease_list");
    const requests = await call<AccessRequestView_Serialize[]>("request_list_pending");
    const grants = await call<GrantView_Serialize[]>("grant_list", { agentId: null });
    const agentIds = ids(agents);
    const itemIds = ids(items);
    const workspaceIds = ids(workspaces);

    for (const lease of leases) {
      expect(agentIds, lease.view.id).toContain(lease.agent_id);
      expect(itemIds, lease.view.id).toContain(lease.view.item_id);
    }
    for (const request of requests) {
      expect(agentIds, request.id).toContain(request.agent_id);
      expect(agents.find((a) => a.id === request.agent_id)?.name).toBe(request.agent_name);
      const item = items.find((i) => i.id === request.item_id);
      expect(item, request.id).toBeDefined();
      expect(item?.title).toBe(request.item_title);
      expect(item?.environment).toBe(request.environment);
    }
    for (const grant of grants) {
      expect(agentIds, grant.id).toContain(grant.agent_id);
      for (const id of grant.selector.workspace_ids) expect(workspaceIds, grant.id).toContain(id);
      for (const id of grant.selector.item_ids) expect(itemIds, grant.id).toContain(id);
    }
  });

  it("gives every item a workspace, and the workspaces count the items", async () => {
    const items = await call<ItemSummaryView_Serialize[]>("item_list", { filter: {} });
    const workspaces = await call<WorkspaceView[]>("workspace_list");
    for (const item of items) expect(workspaces.map((w) => w.slug), item.id).toContain(item.workspace);
    for (const ws of workspaces) expect(ws.item_count, ws.slug).toBe(items.filter((i) => i.workspace === ws.slug).length);
  });

  it("returns the same item from the list and from item_get", async () => {
    const items = await call<ItemSummaryView_Serialize[]>("item_list", { filter: {} });
    for (const item of items) {
      const detail = await call<{ summary: ItemSummaryView_Serialize }>("item_get", { item: item.id });
      expect(detail.summary).toEqual(item);
    }
  });

  it("names only agents, operators and objects that exist in the audit log", async () => {
    const agents = ids(await call<AgentView_Serialize[]>("agent_list"));
    const operators = ids(await call<{ id: string }[]>("vault_list_operators"));
    const known: Record<string, string[]> = {
      item: ids(await call<ItemSummaryView_Serialize[]>("item_list", { filter: {} })),
      request: ids(await call<AccessRequestView_Serialize[]>("request_list_pending")),
      grant: ids(await call<GrantView_Serialize[]>("grant_list", { agentId: null })),
      lease: (await call<LeaseDetailView_Serialize[]>("lease_list")).map((l) => l.view.id),
    };
    const rows = await call<AuditEntryView_Serialize[]>("audit_query", { query: { limit: 100 } });
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      if (row.actor_kind === "agent") expect(agents, `seq ${row.seq}`).toContain(row.actor_id);
      if (row.actor_kind === "operator") expect(operators, `seq ${row.seq}`).toContain(row.actor_id);
      const list = row.target_kind ? known[row.target_kind] : undefined;
      if (list && row.target_id) expect(list, `seq ${row.seq}`).toContain(row.target_id);
    }
  });

  it("shows one network, one status and one settings view with the new fields", async () => {
    const status = await call<VaultStatusView_Serialize>("vault_status");
    expect(status).toMatchObject({ state: "unlocked", kdf: { m_cost_kib: 262_144, t_cost: 3, p_cost: 4 }, last_lock_reason: null, failed_unlocks: 0, free_unlock_tries_left: 5, retry_after_seconds: null });
    const network = await call<NetworkView_Serialize>("network_status");
    expect(network.listening).toBe(true);
    const settings = await call<{ values: Record<string, unknown> }>("settings_get");
    expect(settings.values.idle_lock_seconds).toBe(1800);
  });
});
