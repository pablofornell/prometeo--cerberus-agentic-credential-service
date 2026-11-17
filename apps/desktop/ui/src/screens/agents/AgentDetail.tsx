import { useId, useState } from "react";
import { Link } from "wouter";
import type { AgentKeyView_Serialize, AgentView_Serialize } from "../../bindings";
import { ipc } from "../../ipc/client";
import { pickDirectory } from "../../ipc/dialogs";
import { qk } from "../../ipc/keys";
import { useCan } from "../../state/session";
import { useNow } from "../../state/time";
import { Button, Chip, ConfirmDialog, Icon, IconButton, Notice, Panel, StatusDot, useToast } from "../../ui";
import { GrantSentence, ModeBadge } from "../policies/GrantSentence";
import { QueryGate } from "./QueryGate";
import { SnippetsPanel } from "./SnippetsPanel";
import { RotateKeyDialog, AddKeyDialog } from "./dialogs";
import { ago, inFuture, useAgentsT } from "./format";
import { useAgentGrants, useWorkspaces } from "./queries";
import type { TokenReveal } from "./TokenDialog";
import { useRunner } from "./useRunner";

export const STATUS_TONE = { active: "ok", suspended: "warn", revoked: "off" } as const;

function KeyRow({ k, canEdit, canIssue, now, onRotate, onRevoke, onIssue }: {
  k: AgentKeyView_Serialize;
  canEdit: boolean;
  canIssue: boolean;
  now: number;
  onRotate: () => void;
  onRevoke: () => void;
  onIssue: () => void;
}) {
  const s = useAgentsT();
  const reasonId = useId();
  const revoked = k.revoked_at !== null;
  const expired = !revoked && k.expires_at !== null && Date.parse(k.expires_at) <= now;
  const live = !revoked && !expired;
  const name = `cvt_…${k.hint}`;
  return (
    <tr>
      <td className="mono small">
        {name}
        {k.require_mtls && <> <Chip>{s("keys.mtls")}</Chip></>}
      </td>
      <td>
        <div className="scopes">
          {k.scopes.map((sc) => (
            <span key={sc} className="chip mono">{sc}</span>
          ))}
        </div>
      </td>
      <td className="small">{revoked ? s("keys.revoked") : inFuture(k.expires_at, now, s("keys.noExpiry"))}</td>
      <td className="small">{ago(k.last_used_at, now, s("keys.unused"))}</td>
      <td>
        {canEdit && live && (
          <div className="row-inline">
            <IconButton
              size="sm"
              variant="secondary"
              icon="shield"
              disabled={!canIssue}
              label={s("keys.cert.label", { key: name })}
              {...(canIssue ? {} : { "aria-describedby": reasonId })}
              onClick={onIssue}
            />
            {!canIssue && <span id={reasonId} className="sr-only">{s("keys.cert.ownerOnly")}</span>}
            <Button size="sm" icon="refresh" aria-label={s("keys.rotate.label", { key: name })} onClick={onRotate}>{s("keys.rotate")}</Button>
            <Button size="sm" variant="danger-ghost" aria-label={s("keys.revoke.label", { key: name })} onClick={onRevoke}>{s("keys.revoke")}</Button>
          </div>
        )}
      </td>
    </tr>
  );
}

function GrantsSummary({ agent }: { agent: AgentView_Serialize }) {
  const s = useAgentsT();
  const grants = useAgentGrants(agent.id);
  const workspaces = useWorkspaces();
  return (
    <Panel icon="shield" title={s("grants.title", { name: agent.name })} actions={<Link className="btn sm ghost" href="~/policies">{s("grants.edit")}</Link>}>
      <QueryGate query={grants} action={s("grants.action")} loadingLabel={s("grants.loading")} rows={2}>
        {(list) =>
          list.length === 0 ? (
            <p className="secondary">{s("grants.none", { name: agent.name })}</p>
          ) : (
            <ul className="grants">
              {list.map((g) => (
                <li key={g.id}>
                  <GrantSentence grant={g} workspaces={workspaces.data ?? []} />
                  <ModeBadge mode={g.mode} />
                </li>
              ))}
            </ul>
          )
        }
      </QueryGate>
    </Panel>
  );
}

interface DetailProps {
  agent: AgentView_Serialize;
  canEdit: boolean;
  onReveal: (reveal: TokenReveal) => void;
}

/** One agent: header, keys, snippets and a plain-words summary of its grants. */
export function AgentDetail({ agent, canEdit, onReveal }: DetailProps) {
  const s = useAgentsT();
  const run = useRunner();
  const toast = useToast();
  const isOwner = useCan("owner");
  const now = useNow(30_000);
  const [rotating, setRotating] = useState<AgentKeyView_Serialize | null>(null);
  const [revokingKey, setRevokingKey] = useState<AgentKeyView_Serialize | null>(null);
  const [revokingAgent, setRevokingAgent] = useState(false);
  const [adding, setAdding] = useState<AgentView_Serialize | null>(null);
  const revoked = agent.status === "revoked";
  const suspended = agent.status === "suspended";
  const refresh = [qk.agents()] as const;

  const toggleSuspend = () =>
    run(() => ipc.agentSetStatus(agent.id, suspended ? "active" : "suspended"), {
      done: s(suspended ? "resume.done" : "suspend.done", { name: agent.name }),
      failed: s("action.failed"),
      refresh,
    });

  // The key and certificate files go to a folder the person picks. Their paths and contents are never shown.
  const issueCertificate = async (k: AgentKeyView_Serialize) => {
    let dir: string | null;
    try {
      dir = await pickDirectory({ title: s("keys.cert.pick") });
    } catch {
      toast.push({ tone: "error", title: s("keys.cert.failed") });
      return;
    }
    if (dir === null) return;
    await run(() => ipc.agentIssueClientCert(k.id, dir), { done: s("keys.cert.done", { dir }), failed: s("keys.cert.failed"), refresh });
  };

  return (
    <div className="detail">
      <header>
        <span className={`bot lg-bot${agent.status === "active" ? "" : " off"}`}>
          <Icon name="bot" size={22} />
        </span>
        <div className="grow">
          <h2>{agent.name}</h2>
          <p className="secondary">{agent.description || s("detail.noDescription")}</p>
          <p className="small muted">
            {s("detail.id")} <span className="mono">{agent.id}</span>. <StatusDot tone={STATUS_TONE[agent.status]}>{s(`status.${agent.status}`)}</StatusDot>. {agent.last_seen_at ? s("seen", { when: ago(agent.last_seen_at, now, "") }) : s("seen.never")}
          </p>
        </div>
        {canEdit && !revoked && (
          <div className="row-inline">
            <Button icon={suspended ? "refresh" : "pause"} onClick={() => void toggleSuspend()}>
              {s(suspended ? "detail.resume" : "detail.suspend")}
            </Button>
            <Button variant="danger-ghost" icon="x" onClick={() => setRevokingAgent(true)}>
              {s("detail.revoke")}
            </Button>
          </div>
        )}
      </header>

      {!canEdit && <Notice tone="info" title={s("detail.viewerNote")} />}
      {suspended && <Notice tone="warn" title={s("detail.suspended")} />}
      {revoked && <Notice tone="neutral" title={s("detail.revokedNote")} />}

      <Panel
        flush
        icon="key"
        title={s("keys.title")}
        actions={
          canEdit && !revoked && (
            <Button size="sm" icon="plus" onClick={() => setAdding(agent)}>
              {s("keys.add")}
            </Button>
          )
        }
      >
        {agent.keys.length === 0 ? (
          <p className="small muted pad">{s("keys.none")}</p>
        ) : (
          <table className="grid keys-table">
            <caption className="sr-only">{s("keys.title")}</caption>
            <thead>
              <tr>
                <th scope="col">{s("keys.col.key")}</th>
                <th scope="col">{s("keys.col.scopes")}</th>
                <th scope="col">{s("keys.col.expires")}</th>
                <th scope="col">{s("keys.col.used")}</th>
                <th scope="col"><span className="sr-only">{s("keys.col.actions")}</span></th>
              </tr>
            </thead>
            <tbody>
              {agent.keys.map((k) => (
                <KeyRow key={k.id} k={k} canEdit={canEdit && !revoked} canIssue={isOwner} now={now} onRotate={() => setRotating(k)} onRevoke={() => setRevokingKey(k)} onIssue={() => void issueCertificate(k)} />
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {!revoked && <SnippetsPanel agentId={agent.id} />}
      <GrantsSummary agent={agent} />

      <RotateKeyDialog keyView={rotating} onClose={() => setRotating(null)} onRotated={onReveal} />
      <AddKeyDialog agent={adding} onClose={() => setAdding(null)} onCreated={onReveal} />
      <ConfirmDialog
        open={revokingKey !== null}
        onOpenChange={(open) => !open && setRevokingKey(null)}
        tone="danger"
        title={s("revokeKey.title", { key: revokingKey ? `cvt_…${revokingKey.hint}` : "" })}
        description={s("revokeKey.body")}
        confirmLabel={s("revokeKey.submit")}
        onConfirm={() => {
          const key = revokingKey;
          setRevokingKey(null);
          if (key) void run(() => ipc.agentKeyRevoke(key.id), { done: s("revokeKey.done"), failed: s("action.failed"), refresh });
        }}
      />
      <ConfirmDialog
        open={revokingAgent}
        onOpenChange={setRevokingAgent}
        tone="danger"
        title={s("revoke.title", { name: agent.name })}
        description={s("revoke.body")}
        confirmLabel={s("revoke.submit")}
        onConfirm={() => {
          setRevokingAgent(false);
          void run(() => ipc.agentSetStatus(agent.id, "revoked"), { done: s("revoke.done", { name: agent.name }), failed: s("action.failed"), refresh: [qk.agents(), qk.leases.all()] });
        }}
      />
    </div>
  );
}

