import { useState } from "react";
import type { AgentView_Serialize, GrantView_Serialize, WorkspaceView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc } from "../../ipc/client";
import { Button, ConfirmDialog, EmptyState, IconButton, Panel } from "../../ui";
import { QueryGate } from "../agents/QueryGate";
import { useRunner } from "../agents/useRunner";
import { grantsKey, useAgentGrants } from "../agents/queries";
import { GrantSentence, ModeBadge } from "./GrantSentence";
import { messages } from "./messages";
import { simKey } from "./queries";

interface Props {
  agent: AgentView_Serialize;
  workspaces: readonly WorkspaceView[];
  canEdit: boolean;
  onEdit: (grant: GrantView_Serialize) => void;
  onNew: () => void;
}

/** Every grant of one agent as a plain sentence, with edit and delete. */
export function GrantsPanel({ agent, workspaces, canEdit, onEdit, onNew }: Props) {
  const s = useScreenT(messages);
  const query = useAgentGrants(agent.id);
  const run = useRunner();
  const [deleting, setDeleting] = useState<GrantView_Serialize | null>(null);

  return (
    <Panel icon="shield" title={s("grants.title", { name: agent.name })}>
      <QueryGate query={query} action={s("grants.failed")} loadingLabel={s("load.label")} rows={2}>
        {(grants) =>
          grants.length === 0 ? (
            <EmptyState
              gate
              title={s("grants.empty.title", { name: agent.name })}
              body={s("grants.empty.body")}
              action={
                canEdit ? (
                  <Button variant="primary" icon="plus" onClick={onNew}>
                    {s("grants.empty.action")}
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <ul className="grants" aria-label={s("grants.label")}>
              {grants.map((g) => (
                <li key={g.id}>
                  <GrantSentence grant={g} workspaces={workspaces} id={`grant-${g.id}`} />
                  <ModeBadge mode={g.mode} />
                  {canEdit && (
                    <span className="row-inline">
                      <IconButton icon="edit" size="sm" label={s("grants.edit")} aria-describedby={`grant-${g.id}`} onClick={() => onEdit(g)} />
                      <IconButton icon="trash" size="sm" label={s("grants.delete")} aria-describedby={`grant-${g.id}`} onClick={() => setDeleting(g)} />
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )
        }
      </QueryGate>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        tone="danger"
        title={s("grants.delete.title")}
        description={s("grants.delete.body")}
        confirmLabel={s("grants.delete.confirm")}
        onConfirm={() => {
          const grant = deleting;
          setDeleting(null);
          if (grant) void run(() => ipc.grantDelete(grant.id), { done: s("grants.deleted"), failed: s("save.failed"), refresh: [grantsKey(agent.id), simKey(agent.id)] });
        }}
      />
    </Panel>
  );
}
