import { useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import type { ItemSummaryView_Serialize, LeaseDetailView_Serialize } from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { ipc } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { openOverlay } from "../../shell/uiStore";
import { useRemoteUnsupported } from "../../state/backendMode";
import { useCan } from "../../state/session";
import { formatLeft, useNow } from "../../state/time";
import { Button, ConfirmDialog, EmptyState, EnvBadge, Notice, Panel, Select, TtlRing, useToast } from "../../ui";
import { QueryGate } from "../agents/QueryGate";
import { useAgents } from "../agents/queries";
import { useRunner } from "../agents/useRunner";
import { messages } from "./messages";
import { useItemTitles, useLeases, useSessionItems } from "./queries";
import "./leases.css";

const SHOWN = 5;

type S = ReturnType<typeof useScreenT<typeof messages>>;

function StopBand({ count, onRevokeAll }: { count: number; onRevokeAll: () => void }) {
  const s = useScreenT(messages);
  // Remote mode: lease_revoke_all is local only (DEC-RM-14); "Lock and revoke all" acts on the server vault.
  const localOnly = useRemoteUnsupported("lease_revoke_all");
  return (
    <section className="stop" aria-labelledby="stop-h">
      <div>
        <h2 id="stop-h">{s("stop.title")}</h2>
        <p className="small">{s("stop.body")}</p>
      </div>
      <div className="acts">
        {!localOnly && (
          <Button icon="x" disabled={count === 0} onClick={onRevokeAll}>
            {s("stop.revokeAll")}
          </Button>
        )}
        <Button variant="danger" size="lg" icon="siren" onClick={() => openOverlay("panic")}>
          {s("stop.panic")}
        </Button>
      </div>
    </section>
  );
}

function LeaseTable({ leases, agentName, items, now, onRevoke, s }: {
  leases: readonly LeaseDetailView_Serialize[];
  agentName: (id: string) => string;
  items: readonly ItemSummaryView_Serialize[];
  now: number;
  onRevoke: (lease: LeaseDetailView_Serialize) => void;
  s: S;
}) {
  return (
    <table className="grid">
      <caption className="sr-only">{s("list.caption")}</caption>
      <thead>
        <tr>
          <th scope="col">{s("col.agent")}</th>
          <th scope="col">{s("col.item")}</th>
          <th scope="col">{s("col.permission")}</th>
          <th scope="col">{s("col.from")}</th>
          <th scope="col" className="num right">{s("col.uses")}</th>
          <th scope="col">{s("col.ends")}</th>
          <th scope="col"><span className="sr-only">{s("col.actions")}</span></th>
        </tr>
      </thead>
      <tbody>
        {leases.map((l) => {
          const item = items.find((i) => i.id === l.view.item_id);
          const title = item?.title ?? s("unknown.item", { id: l.view.item_id });
          const agent = agentName(l.agent_id);
          const endsAt = Date.parse(l.view.expires_at);
          const total = Math.max(1, Math.round((endsAt - Date.parse(l.created_at)) / 1000));
          const left = Math.max(0, Math.round((endsAt - now) / 1000));
          return (
            <tr key={l.view.id}>
              <td>{agent}</td>
              <td>
                {title} {item && <EnvBadge env={item.environment} />}
              </td>
              <td className="mono small">{l.view.permission}</td>
              <td className="src">{s(`from.${l.source}`)}</td>
              <td className="num small right">
                {l.view.uses_left === null ? l.uses : s("uses.left", { uses: l.uses, max: l.uses + l.view.uses_left })}
              </td>
              <td>
                <span className="ends">
                  <TtlRing total={total} endsAt={endsAt} size={22} />
                  <span className="ttl-text num">{formatLeft(left)}</span>
                </span>
              </td>
              <td>
                <Button size="sm" aria-label={s("revoke.label", { agent, item: title })} onClick={() => onRevoke(l)}>
                  {s("revoke")}
                </Button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function SessionItems({ canEdit, agentName }: { canEdit: boolean; agentName: (id: string) => string }) {
  const s = useScreenT(messages);
  const query = useSessionItems();
  const now = useNow(1000);
  const run = useRunner();
  const [deleting, setDeleting] = useState<ItemSummaryView_Serialize | null>(null);
  return (
    <Panel flush icon="key" title={s("sessions.title")} actions={<span className="small muted">{s("sessions.note")}</span>}>
      <QueryGate query={query} action={s("sessions.action")} loadingLabel={s("list.loading")} rows={2}>
        {(items) =>
          items.length === 0 ? (
            <p className="small muted pad">{s("sessions.empty")}</p>
          ) : (
            <ul className="rows" aria-label={s("sessions.label")}>
              {items.map((item) => {
                const endsAt = item.expires_at ? Date.parse(item.expires_at) : null;
                const total = endsAt ? Math.max(1, Math.round((endsAt - Date.parse(item.updated_at)) / 1000)) : 1;
                const by = item.created_by.startsWith("agent:") ? agentName(item.created_by.slice(6)) : null;
                const left = endsAt ? formatLeft(Math.max(0, Math.round((endsAt - now) / 1000))) : "";
                const sub = !endsAt
                  ? s("sessions.noEnd", { name: by ?? "" })
                  : by
                    ? s("sessions.by", { name: by, time: left })
                    : s("sessions.byPerson", { time: left });
                return (
                  <li key={item.id}>
                    {endsAt && <TtlRing total={total} endsAt={endsAt} size={28} />}
                    <div className="grow">
                      <div className="title">{item.title}</div>
                      <div className="sub">{sub}</div>
                    </div>
                    <EnvBadge env={item.environment} />
                    {canEdit && (
                      <Button size="sm" variant="danger-ghost" aria-label={s("sessions.delete.label", { title: item.title })} onClick={() => setDeleting(item)}>
                        {s("sessions.delete")}
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          )
        }
      </QueryGate>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        tone="danger"
        title={s("sessions.delete.title")}
        description={s("sessions.delete.body")}
        confirmLabel={s("sessions.delete.confirm")}
        onConfirm={() => {
          const item = deleting;
          setDeleting(null);
          if (item) void run(() => ipc.itemDelete(item.id), { done: s("sessions.deleted"), failed: s("sessions.failed"), refresh: [qk.leases.all(), qk.items.all()] });
        }}
      />
    </Panel>
  );
}

/** Screen 9: active leases with revoke, session items, and the red stop band. */
export default function LeasesScreen() {
  const s = useScreenT(messages);
  const leases = useLeases();
  const agents = useAgents();
  const titles = useItemTitles();
  const canEdit = useCan("operator");
  const now = useNow(1000);
  const run = useRunner();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [agentFilter, setAgentFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [confirmAll, setConfirmAll] = useState(false);

  const agentName = (id: string) => agents.data?.find((a) => a.id === id)?.name ?? s("unknown.agent");
  const sorted = useMemo(
    () => [...(leases.data ?? [])].sort((a, b) => Date.parse(a.view.expires_at) - Date.parse(b.view.expires_at)),
    [leases.data],
  );
  const filtered = agentFilter ? sorted.filter((l) => l.agent_id === agentFilter) : sorted;
  const shown = showAll ? filtered : filtered.slice(0, SHOWN);
  const agentIds = [...new Set(sorted.map((l) => l.agent_id))];

  const revokeAll = async () => {
    setConfirmAll(false);
    try {
      const n = await ipc.leaseRevokeAll();
      await queryClient.invalidateQueries({ queryKey: qk.leases.all() });
      toast.push({ tone: "success", title: n === 1 ? s("revokeAll.done.one") : s("revokeAll.done", { n }) });
    } catch {
      toast.push({ tone: "error", title: s("revoke.failed") });
    }
  };

  return (
    <section className="leases" aria-label={s("list.caption")} data-screen="leases">
      <StopBand count={sorted.length} onRevokeAll={() => setConfirmAll(true)} />
      {!canEdit && <Notice tone="info" title={s("viewer")} />}
      <QueryGate
        query={leases}
        action={s("load.action")}
        loadingLabel={s("list.loading")}
        errorExtra={<p className="small muted center">{s("stale.error")}</p>}
      >
        {() =>
          sorted.length === 0 ? (
            <EmptyState gate title={t("empty.leases.title")} body={t("empty.leases.body")} />
          ) : (
            <Panel
              flush
              icon="timer"
              title={sorted.length === 1 ? s("list.title.one") : s("list.title", { n: sorted.length })}
              actions={
                <>
                  <label className="sr-only" htmlFor="lease-filter">{s("list.filter")}</label>
                  <Select
                    id="lease-filter"
                    className="filter"
                    value={agentFilter}
                    onChange={(e) => setAgentFilter(e.target.value)}
                    options={[{ value: "", label: s("list.all") }, ...agentIds.map((id) => ({ value: id, label: agentName(id) }))]}
                  />
                </>
              }
            >
              {filtered.length === 0 ? (
                <p className="small muted pad">{s("no.match")}</p>
              ) : (
                <LeaseTable
                  leases={shown}
                  agentName={agentName}
                  items={titles.data ?? []}
                  now={now}
                  s={s}
                  onRevoke={(l) => void run(() => ipc.leaseRevoke(l.view.id), { done: s("revoke.done"), failed: s("revoke.failed"), refresh: [qk.leases.all()] })}
                />
              )}
              {filtered.length > SHOWN && (
                <p className="small muted foot-note">
                  {!showAll && <>{s("list.showing", { n: SHOWN })} </>}
                  <Button size="sm" variant="ghost" onClick={() => setShowAll(!showAll)}>
                    {showAll ? s("list.showLess") : s("list.showAll", { n: filtered.length })}
                  </Button>
                </p>
              )}
            </Panel>
          )
        }
      </QueryGate>
      <SessionItems canEdit={canEdit} agentName={agentName} />
      <ConfirmDialog
        open={confirmAll}
        onOpenChange={setConfirmAll}
        tone="danger"
        title={s("revokeAll.title", { n: sorted.length })}
        description={s("revokeAll.body")}
        confirmLabel={s("revokeAll.confirm")}
        onConfirm={() => void revokeAll()}
      />
    </section>
  );
}
