import { useCallback, useEffect, useState } from "react";
import { t } from "../../i18n";
import { Button, EmptyState, Icon, StatusDot } from "../../ui";
import { useHashQuery } from "../../shell/location";
import { PageActions } from "../../shell/PageActions";
import { useRemoteUnsupported } from "../../state/backendMode";
import { useCan } from "../../state/session";
import { useNow } from "../../state/time";
import { AgentDetail, STATUS_TONE } from "./AgentDetail";
import { CreateAgentDialog } from "./dialogs";
import { ago, useAgentsT } from "./format";
import { QueryGate } from "./QueryGate";
import { useAgents } from "./queries";
import { TokenDialog, type TokenReveal } from "./TokenDialog";
import type { AgentView_Serialize } from "../../bindings";
import "./agents.css";

function AgentList({ agents, selectedId, onSelect }: { agents: readonly AgentView_Serialize[]; selectedId: string | null; onSelect: (id: string) => void }) {
  const s = useAgentsT();
  const now = useNow(30_000);
  return (
    <section className="panel flush" aria-labelledby="agent-list-h">
      <header>
        <h2 id="agent-list-h">{agents.length === 1 ? s("list.title.one") : s("list.title", { count: agents.length })}</h2>
      </header>
      <ul className="rows" aria-label={s("list.label")}>
        {agents.map((a) => (
          <li key={a.id} className="interactive">
            <button type="button" className="row-btn" aria-current={a.id === selectedId ? "true" : undefined} onClick={() => onSelect(a.id)}>
              <span className={`bot${a.status === "active" ? "" : " off"}`}>
                <Icon name="bot" />
              </span>
              <span className="grow">
                <span className="title">{a.name}</span>
                <span className="sub">{a.last_seen_at ? s("seen", { when: ago(a.last_seen_at, now, "") }) : s("seen.never")}</span>
              </span>
              <StatusDot tone={STATUS_TONE[a.status]}>{s(`status.${a.status}`)}</StatusDot>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Screen 6: agents, one-time tokens, snippets and what each agent can do. */
export default function AgentsScreen() {
  const s = useAgentsT();
  const query = useAgents();
  // Remote mode: the server lists its agents, but making and changing them is local only for now (DEC-RM-14).
  const localOnly = useRemoteUnsupported("agent_create");
  const canEdit = useCan("operator") && !localOnly;
  const hashQuery = useHashQuery();
  const [picked, setPicked] = useState<string | null>(() => hashQuery.get("agent"));
  const [creating, setCreating] = useState(() => hashQuery.get("new") === "1");
  const [reveal, setReveal] = useState<TokenReveal | null>(null);
  const clearReveal = useCallback(() => setReveal(null), []);

  // The token must not stay in memory after the person leaves this screen.
  useEffect(() => clearReveal, [clearReveal]);

  const onCreated = (agentId: string, next: TokenReveal) => {
    setPicked(agentId);
    setReveal(next);
  };

  return (
    <section aria-label={s("list.label")} data-screen="agents">
      {canEdit && (
        <PageActions>
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
            {s("new")}
          </Button>
        </PageActions>
      )}
      <QueryGate query={query} action={s("load.action")} loadingLabel={s("list.loading")}>
        {(agents) => {
          if (agents.length === 0) {
            return (
              <EmptyState
                as="h2"
                icon="bot"
                title={t("empty.agents.title")}
                body={s("empty.body")}
                action={
                  canEdit ? (
                    <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
                      {s("new")}
                    </Button>
                  ) : undefined
                }
              />
            );
          }
          const selected = agents.find((a) => a.id === picked) ?? agents[0];
          return (
            <div className="agents">
              <AgentList agents={agents} selectedId={selected?.id ?? null} onSelect={setPicked} />
              {selected && <AgentDetail key={selected.id} agent={selected} canEdit={canEdit} localOnly={localOnly} onReveal={setReveal} />}
            </div>
          );
        }}
      </QueryGate>
      <CreateAgentDialog open={creating && canEdit} onOpenChange={setCreating} onCreated={onCreated} />
      <TokenDialog reveal={reveal} onDone={clearReveal} />
    </section>
  );
}
