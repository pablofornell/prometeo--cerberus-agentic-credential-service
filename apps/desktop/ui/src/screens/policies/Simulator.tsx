import { useScreenT } from "../../i18n";
import type { GrantMode, SimulationRow_Serialize } from "../../bindings";
import { EnvBadge, Icon, Panel, Button } from "../../ui";
import { QueryGate } from "../agents/QueryGate";
import { messages } from "./messages";
import { useItemEnvs, useSimulation } from "./queries";

type S = ReturnType<typeof useScreenT<typeof messages>>;

const CLASS: Record<string, string> = { auto: "m-auto", ask_once: "m-once", ask_always: "m-always", deny: "m-deny" };

/** One result in plain words, and its colour class. The words carry the meaning; colour only confirms it. */
export function describeDecision(row: SimulationRow_Serialize, s: S): { text: string; className: string } {
  const d = row.decision;
  switch (d.outcome) {
    case "allow": {
      const mode: GrantMode = d.mode ?? "ask_always";
      if (mode === "deny") return { text: s("sim.allow.deny"), className: CLASS.deny ?? "" };
      return { text: s(`sim.allow.${mode}`, { verb: s(`verb.${row.permission}`) }), className: CLASS[mode] ?? "" };
    }
    case "deny":
      return { text: s("sim.deny"), className: "m-deny" };
    case "no_grant":
      return { text: s("sim.no_grant"), className: "m-none" };
    case "condition_failed":
      return { text: s("sim.condition_failed"), className: "m-deny" };
    case "reason_required":
      return { text: s("sim.reason_required"), className: "m-always" };
    case "grant_rate_limited":
      return { text: s("sim.grant_rate_limited", { n: d.retry_after_seconds ?? 0 }), className: "m-always" };
    default:
      return { text: s("sim.unknown"), className: "m-none" };
  }
}

/** "What can agent X see?" One row for each item and permission the policy engine answers for. */
export function Simulator({ agentId, agentName }: { agentId: string; agentName: string }) {
  const s = useScreenT(messages);
  const query = useSimulation(agentId);
  const items = useItemEnvs();
  const envOf = (id: string) => items.data?.find((i) => i.id === id)?.environment;
  return (
    <Panel
      flush
      icon="search"
      title={s("sim.title", { name: agentName })}
      actions={
        <Button size="sm" icon="refresh" loading={query.isFetching && !query.isPending} onClick={() => void query.refetch()}>
          {s("sim.run")}
        </Button>
      }
    >
      <QueryGate query={query} action={s("sim.failed")} loadingLabel={s("sim.loading")} rows={3}>
        {(rows) =>
          rows.length === 0 ? (
            <p className="small muted sim-empty"><Icon name="info" /> {s("sim.empty")}</p>
          ) : (
            <table className="grid">
              <caption className="sr-only">{s("sim.caption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{s("sim.col.item")}</th>
                  <th scope="col">{s("sim.col.env")}</th>
                  <th scope="col">{s("sim.col.perm")}</th>
                  <th scope="col">{s("sim.col.result")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const result = describeDecision(row, s);
                  const env = envOf(row.item_id);
                  return (
                    <tr key={`${row.item_id}-${row.permission}`}>
                      <td>{row.title}</td>
                      <td>{env && <EnvBadge env={env} />}</td>
                      <td className="small secondary">{s(`perm.${row.permission}`)}</td>
                      <td><span className={`mode ${result.className}`}>{result.text}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )
        }
      </QueryGate>
    </Panel>
  );
}
