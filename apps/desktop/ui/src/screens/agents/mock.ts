// Dev mock of the agent commands. It keeps its state in memory, so create, rotate and revoke work in the browser.
// Switches: `?mock_agents=empty|error|slow`.
import type { AgentView_Serialize } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { devFlag, FAKE_TOKEN, fixtureAgents, scenario, secondsFromNow, sleep } from "../../ipc/mock/fixtures";

type Args = Record<string, unknown> | undefined;
const text = (args: Args, name: string): string => String((args as Record<string, unknown>)[name]);

/** A fresh set of handlers with its own state. Tests call this for each test. */
export function agentHandlers(): MockHandlers {
  let agents = fixtureAgents();
  let counter = 0;
  const replace = (next: AgentView_Serialize): AgentView_Serialize => {
    agents = agents.map((a) => (a.id === next.id ? next : a));
    return next;
  };
  const find = (id: string): AgentView_Serialize => {
    const agent = agents.find((a) => a.id === id);
    if (!agent) throw mockError("not_found", "no such agent");
    return agent;
  };
  const newKey = (scopes: AgentView_Serialize["keys"][number]["scopes"], days: number | null, ips: string[]) => {
    counter += 1;
    return {
      id: `key_new${counter}`,
      hint: String(1000 + counter),
      scopes,
      ip_allowlist: ips,
      expires_at: days === null ? null : secondsFromNow(days * 86_400),
      revoked_at: null,
      last_used_at: null,
      require_mtls: false,
    };
  };
  return {
    agent_list: async () => {
      const flag = devFlag("mock_agents") ?? (scenario() === "error" ? "error" : null);
      if (flag === "slow") await sleep(60_000);
      if (flag === "error") throw mockError("internal", "the agent list did not load");
      return flag === "empty" ? [] : agents;
    },
    agent_create: (args) => {
      const input = (args as { input: { name: string; description: string }; key: { scopes: never[]; lifetime_days: number | null; ip_allowlist: string[] } });
      if (input.input.name.trim() === "") throw mockError("validation_failed", "invalid input", { fields: [{ field: "name", problem: "must not be empty" }] });
      counter += 1;
      const agent: AgentView_Serialize = {
        id: `agt_new${counter}`,
        name: input.input.name,
        description: input.input.description,
        status: "active",
        keys: [newKey(input.key.scopes, input.key.lifetime_days, input.key.ip_allowlist)],
        last_seen_at: null,
      };
      agents = [...agents, agent];
      return { agent, token: FAKE_TOKEN };
    },
    agent_update: (args) => replace({ ...find(text(args, "agent")), ...(args as { input: { name: string; description: string } }).input }),
    agent_set_status: (args) => replace({ ...find(text(args, "agent")), status: (args as { status: AgentView_Serialize["status"] }).status }),
    agent_key_create: (args) => {
      const a = args as { agentId: string; key: { scopes: never[]; lifetime_days: number | null; ip_allowlist: string[] } };
      const agent = find(a.agentId);
      const key = newKey(a.key.scopes, a.key.lifetime_days, a.key.ip_allowlist);
      replace({ ...agent, keys: [key, ...agent.keys] });
      return { key, token: FAKE_TOKEN };
    },
    agent_key_rotate: (args) => {
      const keyId = text(args, "keyId");
      const agent = agents.find((a) => a.keys.some((k) => k.id === keyId));
      const old = agent?.keys.find((k) => k.id === keyId);
      if (!agent || !old) throw mockError("not_found", "no such key");
      const key = newKey(old.scopes, 90, old.ip_allowlist);
      replace({ ...agent, keys: [key, ...agent.keys] });
      return { key, token: FAKE_TOKEN };
    },
    agent_key_revoke: (args) => {
      const keyId = text(args, "keyId");
      const agent = agents.find((a) => a.keys.some((k) => k.id === keyId));
      if (!agent) throw mockError("not_found", "no such key");
      replace({ ...agent, keys: agent.keys.map((k) => (k.id === keyId ? { ...k, revoked_at: secondsFromNow(0) } : k)) });
      return null;
    },
    agent_snippets: (args) => {
      find(text(args, "agentId"));
      return {
        mcp_json: '{\n  "mcpServers": {\n    "cerberus": {\n      "url": "https://localhost:7373/mcp",\n      "headers": { "Authorization": "Bearer ${CERBERUS_TOKEN}" }\n    }\n  }\n}\n',
        curl: 'curl --cacert cerberus-ca.pem -H "Authorization: Bearer $CERBERUS_TOKEN" https://localhost:7373/v1/status\n',
        env: `export CERBERUS_URL=https://localhost:7373\nexport CERBERUS_AGENT_ID=${text(args, "agentId")}\nexport CERBERUS_TOKEN=<paste the token here>\nexport NODE_EXTRA_CA_CERTS=/path/to/cerberus-ca.pem\n`,
      };
    },
    agent_issue_client_cert: (args) => {
      const keyId = text(args, "keyId");
      if (!agents.some((a) => a.keys.some((k) => k.id === keyId))) throw mockError("not_found", "no such key");
      const dir = text(args, "destDir").replace(/\/$/, "");
      return { cert_path: `${dir}/${keyId}.crt`, key_path: `${dir}/${keyId}.key`, sha256: "c1a5e0f3d9b47286a1f0c3e5d7b9a2c4e6f8091a3b5d7f9e1c3a5b7d9f0e2c4a" };
    },
  };
}

export const handlers: MockHandlers = agentHandlers();
