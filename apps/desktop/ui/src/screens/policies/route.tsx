import { useState } from "react";
import { Link } from "wouter";
import type { GrantView_Serialize } from "../../bindings";
import { useScreenT } from "../../i18n";
import { useHashQuery } from "../../shell/location";
import { useCan } from "../../state/session";
import { EmptyState } from "../../ui";
import { QueryGate } from "../agents/QueryGate";
import { useAgents, useWorkspaces } from "../agents/queries";
import { draftFromGrant, emptyDraft, type Draft } from "./draft";
import { GrantBuilder } from "./GrantBuilder";
import { GrantsPanel } from "./GrantsPanel";
import { messages } from "./messages";
import { Simulator } from "./Simulator";
import "./policies.css";

/** Screen 7: grants in plain words, and the simulator. */
export default function PoliciesScreen() {
  const s = useScreenT(messages);
  const agents = useAgents();
  const workspaces = useWorkspaces();
  const canEdit = useCan("operator");
  const hashQuery = useHashQuery();
  const [pickedId, setPickedId] = useState<string | null>(() => hashQuery.get("agent"));
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [focusBuilder, setFocusBuilder] = useState(() => hashQuery.get("new") === "1");

  const edit = (grant: GrantView_Serialize) => {
    setDraft(draftFromGrant(grant));
    setFocusBuilder(true);
  };

  return (
    <section aria-label={s("grants.label")} data-screen="policies">
      <QueryGate query={agents} action={s("load.action")} loadingLabel={s("load.label")}>
        {(list) => {
          if (list.length === 0) {
            return (
              <EmptyState
                as="h2"
                icon="bot"
                title={s("agent.none.title")}
                body={s("agent.none.body")}
                action={
                  <Link className="btn primary" href="~/agents?new=1">
                    {s("agent.none.action")}
                  </Link>
                }
              />
            );
          }
          const agent = list.find((a) => a.id === pickedId) ?? list[0];
          if (!agent) return null;
          const spaces = workspaces.data ?? [];
          return (
            <div className="policies">
              <div className="agent-pick">
                <label htmlFor="agent-pick" className="secondary">{s("agent.pick")}</label>
                <select
                  id="agent-pick"
                  className="input select"
                  value={agent.id}
                  onChange={(e) => {
                    setPickedId(e.target.value);
                    setDraft(emptyDraft());
                  }}
                >
                  {list.map((a) => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
                <span className="small muted">{s("agent.note")}</span>
              </div>
              <GrantBuilder key={`${agent.id}-${draft.id ?? "new"}`} agent={agent} workspaces={spaces} draft={draft} setDraft={setDraft} canEdit={canEdit} focusOnMount={focusBuilder} />
              <div className="cols c-2">
                <GrantsPanel agent={agent} workspaces={spaces} canEdit={canEdit} onEdit={edit} onNew={() => setFocusBuilder(true)} />
                <Simulator agentId={agent.id} agentName={agent.name} />
              </div>
            </div>
          );
        }}
      </QueryGate>
    </section>
  );
}

