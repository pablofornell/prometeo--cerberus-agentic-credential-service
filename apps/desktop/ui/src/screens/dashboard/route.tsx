import { useState } from "react";
import { useLocation } from "wouter";
import type {
  AccessRequestView_Serialize,
  AgentView_Serialize,
  ItemSummaryView_Serialize,
  KdfParamsView,
  LeaseDetailView_Serialize,
  NetworkView_Serialize,
} from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { useRemote } from "../../state/backendMode";
import type { IpcFailure } from "../../ipc/client";
import { useVaultStatus } from "../../ipc/queries";
import { useHashQuery } from "../../shell/location";
import { agentFeedStore, alertsStore } from "../../state/live";
import { useAutolockSeconds, useRole, useSessionLabel } from "../../state/session";
import { formatDuration, formatLeft, useCountdown, useNow } from "../../state/time";
import {
  Button,
  EmptyState,
  EnvBadge,
  ErrorState,
  errorText,
  GateMark,
  Icon,
  Notice,
  Panel,
  Skeleton,
  showInvisible,
  StatusDot,
  TtlRing,
  type StatusTone,
} from "../../ui";
import { costSummary } from "../create/Steps";
import { kindLabel } from "../vault/kinds";
import { ConnectGuide } from "./ConnectGuide";
import { clockTime, feedTone, hourMinute, PERMISSION_ICON, PERMISSION_TEXT, requestTotalSeconds, secondsUntil } from "./format";
import { messages } from "./messages";
import { useChainReport, useDashboardData, useSeedFeed } from "./queries";
import "./dashboard.css";

type M = ReturnType<typeof useScreenT<typeof messages>>;

/** Inline state of one part that failed. A viewer who is not allowed gets a plain line, not an error. */
function PartError({ error, onRetry, m }: { error: IpcFailure; onRetry: () => void; m: M }) {
  const blocked = error.code === "role_not_allowed" || error.code === "forbidden";
  return (
    <div className="panel-note" role={blocked ? undefined : "alert"}>
      <span>{blocked ? m("panel.roleBlocked") : `${m("panel.error")} ${errorText(error.error)}`}</span>
      {!blocked && (
        <Button size="sm" icon="refresh" onClick={onRetry}>
          {m("panel.retry")}
        </Button>
      )}
    </div>
  );
}

const plural = (m: M, key: "band.agents" | "band.waiting" | "band.leases", n: number) =>
  n === 1 ? m(`${key}.one`) : m(key, { n });

/** The sentence for an event type. Types without a text show the raw type. */
const verbText = (m: M, eventType: string): string => {
  const key = `feed.verb.${eventType}`;
  return key in messages ? m(key as keyof typeof messages) : m("feed.verb.fallback", { type: eventType });
};

function LeftText({ endsAt, label, m }: { endsAt: number; label: "expires.lease" | "expires.item"; m: M }) {
  const left = useCountdown(endsAt) ?? 0;
  return <>{m(label, { time: formatLeft(left) })}</>;
}

/** Alerts that the backend sends as events, plus the header and chain checks. They are loud on purpose. */
function Alerts({ agents, chainBroken, headerOk, m }: { agents: AgentView_Serialize[]; chainBroken: number | null; headerOk: boolean; m: M }) {
  const [, navigate] = useLocation();
  const alerts = alertsStore.use();
  const name = (id: string) => agents.find((a) => a.id === id)?.name ?? m("feed.unknownAgent");
  const seen = new Set<string>();
  const massRead = alerts.massRead.filter((a) => (seen.has(a.agent_id) ? false : (seen.add(a.agent_id), true))).slice(0, 3);
  return (
    <>
      {massRead.map((a) => (
        <Notice
          key={a.agent_id}
          tone="bad"
          title={m("alert.massRead", { agent: name(a.agent_id), n: a.distinct_items })}
          actions={
            <>
              <Button size="sm" onClick={() => navigate(`~/agents?agent=${encodeURIComponent(a.agent_id)}`)}>
                {m("alert.massRead.suspend")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => navigate("~/audit")}>
                {m("alert.openAudit")}
              </Button>
            </>
          }
        >
          {m("alert.massRead.body")}
        </Notice>
      ))}
      {alerts.integrity.slice(0, 3).map((a) => (
        <Notice key={`${a.table}/${a.row_id}`} tone="bad" title={m("alert.integrity")} actions={<Button size="sm" onClick={() => navigate("~/audit")}>{m("alert.openAudit")}</Button>}>
          {m("alert.integrity.body", { table: a.table, row: a.row_id })}
        </Notice>
      ))}
      {(alerts.headerMismatch || !headerOk) && (
        <Notice tone="bad" title={m("alert.header")}>
          {m("alert.header.body")}
        </Notice>
      )}
      {chainBroken !== null && (
        <Notice tone="bad" title={m("alert.chain", { seq: chainBroken.toLocaleString() })} actions={<Button size="sm" onClick={() => navigate("~/audit")}>{m("alert.seeDetails")}</Button>}>
          {m("alert.chain.body")}
        </Notice>
      )}
    </>
  );
}

interface BandProps {
  m: M;
  waiting: number;
  leases: number;
  agents: number;
  /** `null` in remote mode: the connect guide is for agents of the local vault. */
  onConnect: (() => void) | null;
}

/** One stat of the header: the number as a figure and its own translated label. The whole sentence stays as the screen-reader text. */
function Figure({ m, k, n, tone }: { m: M; k: "band.agents" | "band.waiting" | "band.leases"; n: number; tone?: "warn" }) {
  return (
    <div className={tone ? `fig ${tone}` : "fig"}>
      <span className="sr-only">{plural(m, k, n)}</span>
      <span className="n" aria-hidden="true">{n}</span>
      <span className="l" aria-hidden="true">{n === 1 ? m(`${k}.label.one`) : m(`${k}.label`)}</span>
    </div>
  );
}

function Band({ m, waiting, leases, agents, onConnect }: BandProps) {
  const status = useVaultStatus().data;
  const label = useSessionLabel();
  const role = useRole();
  const left = useAutolockSeconds();
  const remote = useRemote();
  return (
    <section className="band" aria-labelledby="dash-band-h">
      <GateMark size={48} mode="open" />
      <div>
        <h2 id="dash-band-h">{remote ? m("band.title.remote", { label: remote.label }) : m("band.title")}</h2>
        <div className="facts">
          {label && role && <span>{m("band.signedIn", { name: label, role })}</span>}
          <span>
            {left === null ? (
              m("band.autolockOff")
            ) : (
              <>
                {m("band.autolock.pre")} <b>{formatLeft(left)}</b> {m("band.autolock.post")}
              </>
            )}
          </span>
          {status?.hard_lock_at && <span>{m("band.hardLock", { time: hourMinute(status.hard_lock_at) })}</span>}
        </div>
      </div>
      <div className="acts">
        {onConnect && <Button icon="plus" onClick={onConnect}>{m("band.connect")}</Button>}
      </div>
      <div className="figs" role="group" aria-label={m("band.trace")}>
        <Figure m={m} k="band.agents" n={agents} />
        <Figure m={m} k="band.waiting" n={waiting} tone={waiting > 0 ? "warn" : undefined} />
        <Figure m={m} k="band.leases" n={leases} />
      </div>
      {role === "viewer" && <p className="small viewer-note">{m("band.viewerNote")}</p>}
    </section>
  );
}

function Queue({ requests, m, now }: { requests: AccessRequestView_Serialize[]; m: M; now: number }) {
  const [, navigate] = useLocation();
  return (
    <Panel
      title={m("queue.title")}
      icon="bell"
      flush
      actions={<Button size="sm" variant="ghost" onClick={() => navigate("~/approvals")}>{m("queue.open")}</Button>}
    >
      {requests.length === 0 ? (
        <p className="panel-note">{m("queue.empty")}</p>
      ) : (
        <ul className="rows queue">
          {requests.map((r) => (
            <li key={r.id} className={r.environment === "prod" ? "prod" : undefined}>
              <span className="kind-ico"><Icon name={PERMISSION_ICON[r.permission] ?? "key"} size={16} /></span>
              <div className="grow">
                <div className="title">{r.item_title}</div>
                <div className="sub">{r.role_label ? m("queue.kindRole", { kind: kindLabel(r.item_kind), role: showInvisible(r.role_label) }) : kindLabel(r.item_kind)}</div>
                <div className="sub">
                  {m("queue.row", {
                    agent: r.agent_name,
                    permission: PERMISSION_TEXT[r.permission],
                    ttl: r.requested_ttl_seconds ? m("queue.ttl", { time: formatDuration(r.requested_ttl_seconds) }) : "",
                  })}
                </div>
              </div>
              <EnvBadge env={r.environment} />
              <TtlRing total={requestTotalSeconds(r)} left={Math.max(0, secondsUntil(r.expires_at, now))} endsAt={Date.parse(r.expires_at)} size={24} />
              <Button size="sm" aria-label={m("queue.review.label", { item: r.item_title })} onClick={() => navigate("~/approvals")}>
                {m("queue.review")}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

interface HealthRow {
  key: string;
  tone: StatusTone;
  title: string;
  sub: string;
  action?: { label: string; run: () => void };
}

function Health({
  m,
  network,
  status,
  localOnly,
}: {
  m: M;
  network: { data?: NetworkView_Serialize; error: IpcFailure | null; isPending: boolean };
  /** Remote mode: the chain check and the TLS listener are the server's (`cerberusd status`). */
  localOnly: boolean;
  status: { memlock_ok: boolean; os_hook_ok: boolean; header_ok: boolean; kdf: KdfParamsView | null };
}) {
  const [, navigate] = useLocation();
  const chain = useChainReport();
  const now = useNow(60_000);
  const rows: HealthRow[] = [];

  const verify = { label: m("health.verify"), run: () => void chain.refetch() };
  if (localOnly) rows.push({ key: "server", tone: "off", title: t("remote.unsupported"), sub: m("health.remote.sub") });
  else if (chain.isPending || chain.isFetching) rows.push({ key: "chain", tone: "off", title: m("health.chain.checking"), sub: "" });
  else if (chain.isError) rows.push({ key: "chain", tone: "warn", title: m("health.chain.error"), sub: errorText(chain.error.error), action: verify });
  else if (chain.data.ok) rows.push({ key: "chain", tone: "ok", title: m("health.chain.ok"), sub: m("health.chain.okSub", { count: chain.data.count.toLocaleString() }), action: verify });
  else rows.push({ key: "chain", tone: "bad", title: m("health.chain.bad", { seq: (chain.data.broken_seq ?? 0).toLocaleString() }), sub: m("health.chain.badSub"), action: { label: m("alert.openAudit"), run: () => navigate("~/audit") } });

  const settingsAction = { label: m("health.settings"), run: () => navigate("~/settings") };
  if (localOnly) {
    // Shown once, in the chain row above.
  } else if (network.isPending) rows.push({ key: "tls", tone: "off", title: m("connect.loading"), sub: "" });
  else if (network.data) {
    const net = network.data;
    if (!net.listening) rows.push({ key: "tls", tone: "bad", title: m("health.tls.down"), sub: net.error ?? m("health.tls.downNoReason"), action: settingsAction });
    else if (!net.leaf_not_after) rows.push({ key: "tls", tone: "warn", title: m("health.tls.unknown"), sub: "" });
    else {
      const days = Math.floor((Date.parse(net.leaf_not_after) - now) / 86_400_000);
      if (days < 0) rows.push({ key: "tls", tone: "bad", title: m("health.tls.expired"), sub: m("health.tls.expiredSub"), action: settingsAction });
      else rows.push({ key: "tls", tone: days <= 30 ? "warn" : "ok", title: m(days <= 30 ? "health.tls.warn" : "health.tls.ok", { days }), sub: m("health.tls.sub") });
    }
  } else if (network.error) rows.push({ key: "tls", tone: "warn", title: m("health.tls.unknown"), sub: errorText(network.error.error) });

  rows.push(
    status.kdf
      ? { key: "kdf", tone: "ok", title: m("health.kdf", costSummary(status.kdf)), sub: m("health.kdf.sub", costSummary(status.kdf)) }
      : { key: "kdf", tone: "off", title: m("health.kdf.none"), sub: m("health.kdf.noneSub") },
  );
  rows.push(status.memlock_ok
    ? { key: "mem", tone: "ok", title: m("health.mem.ok"), sub: m("health.mem.okSub") }
    : { key: "mem", tone: "warn", title: m("health.mem.bad"), sub: m("health.mem.badSub") });
  rows.push(status.os_hook_ok
    ? { key: "hook", tone: "ok", title: m("health.hook.ok"), sub: localOnly ? m("health.hook.remoteSub") : m("health.hook.okSub") }
    : { key: "hook", tone: "warn", title: m("health.hook.bad"), sub: m("health.hook.badSub"), action: settingsAction });
  if (!status.header_ok) rows.push({ key: "header", tone: "bad", title: m("health.header.bad"), sub: m("health.header.badSub") });

  const word: Record<StatusTone, string> = { ok: m("health.ok"), warn: m("health.warn"), bad: m("health.bad"), off: m("health.off") };
  return (
    <Panel title={m("health.title")} icon="shield" flush>
      <ul className="rows health" aria-busy={chain.isFetching || undefined}>
        {rows.map((r) => (
          <li key={r.key}>
            <StatusDot tone={r.tone}><span className="sr-only">{word[r.tone]}</span></StatusDot>
            <div className="grow">
              <span>{r.title}</span>
              {r.sub && <span className="small muted">{r.sub}</span>}
            </div>
            {r.action && <Button size="sm" variant="ghost" onClick={r.action.run}>{r.action.label}</Button>}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Feed({ m, agents, items }: { m: M; agents: AgentView_Serialize[]; items: ItemSummaryView_Serialize[] }) {
  const feed = agentFeedStore.use();
  return (
    <Panel title={m("feed.title")} icon="activity" flush actions={<StatusDot tone="ok">{m("feed.live")}</StatusDot>}>
      {feed.length === 0 ? (
        <p className="panel-note">{m("feed.empty")}</p>
      ) : (
        <ol className="rows feed" aria-live="polite" aria-relevant="additions" aria-label={m("feed.title")}>
          {feed.slice(0, 12).map((a) => {
            const tone = feedTone(a.event_type);
            const item = a.item_id ? items.find((i) => i.id === a.item_id) : undefined;
            return (
              <li key={`${a.at}|${a.agent_id}|${a.event_type}|${a.item_id ?? ""}`}>
                <time dateTime={a.at}>{clockTime(a.at)}</time>
                <div className="what">
                  <span className="ag">{agents.find((x) => x.id === a.agent_id)?.name ?? m("feed.unknownAgent")}</span>{" "}
                  {verbText(m, a.event_type)}
                  {item && <> <span className="target">{item.title}</span></>}
                </div>
                <span className={`out ${tone}`}>{m(`feed.out.${tone}`)}</span>
              </li>
            );
          })}
        </ol>
      )}
    </Panel>
  );
}

interface Expiring {
  key: string;
  title: string;
  kind: "lease" | "item";
  endsAt: number;
  total: number;
  env: ItemSummaryView_Serialize["environment"] | null;
}

function Expires({
  m,
  leases,
  items,
  agents,
  now,
}: {
  m: M;
  leases: LeaseDetailView_Serialize[];
  items: ItemSummaryView_Serialize[];
  agents: AgentView_Serialize[];
  now: number;
}) {
  const [, navigate] = useLocation();
  const rows: Expiring[] = [];
  for (const l of leases) {
    const item = items.find((i) => i.id === l.view.item_id);
    rows.push({
      key: `l-${l.view.id}`,
      title: m("expires.leaseTitle", { agent: agents.find((a) => a.id === l.agent_id)?.name ?? m("feed.unknownAgent"), item: item?.title ?? m("expires.unknownItem") }),
      kind: "lease",
      endsAt: Date.parse(l.view.expires_at),
      total: Math.max(1, Math.round((Date.parse(l.view.expires_at) - Date.parse(l.created_at)) / 1000)),
      env: item?.environment ?? null,
    });
  }
  for (const i of items) {
    if (i.expires_at) rows.push({ key: `i-${i.id}`, title: i.title, kind: "item", endsAt: Date.parse(i.expires_at), total: Math.max(1, Math.round((Date.parse(i.expires_at) - Date.parse(i.updated_at)) / 1000)), env: i.environment });
  }
  const soon = rows.filter((r) => r.endsAt > now).sort((a, b) => a.endsAt - b.endsAt).slice(0, 6);
  return (
    <Panel title={m("expires.title")} icon="timer" flush actions={<Button size="sm" variant="ghost" onClick={() => navigate("~/leases")}>{m("expires.all")}</Button>}>
      {soon.length === 0 ? (
        <p className="panel-note">{m("expires.empty")}</p>
      ) : (
        <ul className="rows" aria-label={m("expires.title")}>
          {soon.map((r) => (
            <li key={r.key}>
              <TtlRing total={r.total} endsAt={r.endsAt} size={28} />
              <div className="grow">
                <div className="title">{r.title}</div>
                <div className="sub"><LeftText endsAt={r.endsAt} label={r.kind === "lease" ? "expires.lease" : "expires.item"} m={m} /></div>
              </div>
              {r.env && <EnvBadge env={r.env} />}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function DashboardScreen() {
  const m = useScreenT(messages);
  const [, navigate] = useLocation();
  const hashQuery = useHashQuery();
  // `?connect=1` (from the command palette) opens the guide at once.
  const [connectOpen, setConnectOpen] = useState(() => hashQuery.get("connect") === "1");
  const status = useVaultStatus().data;
  const { agents, items, leases, requests, network, localOnly } = useDashboardData();
  const chain = useChainReport();
  const now = useNow(1000);
  useSeedFeed();

  const agentList = agents.data ?? [];
  const itemList = items.data ?? [];
  const brokenSeq = chain.data && !chain.data.ok ? (chain.data.broken_seq ?? 0) : null;

  const core = <ConnectGuide open={connectOpen} onOpenChange={setConnectOpen} />;

  if (!status) return null;

  if (agents.isPending || items.isPending) {
    return (
      <section aria-label={t("screen.dashboard")} data-screen="dashboard" className="dash" aria-busy="true">
        <Skeleton label={m("loading")} variant="block" />
        <div className="cols c-main-side">
          {[0, 1].map((i) => (
            <div key={i} className="panel flush">
              <header aria-hidden="true"><span className="skel" /></header>
              <div className="body"><Skeleton label={m("loading")} rows={3} /></div>
            </div>
          ))}
        </div>
      </section>
    );
  }

  const failure = [agents, items].find((q) => q.isError && q.error.code !== "role_not_allowed" && q.error.code !== "forbidden");
  if (failure?.error) {
    const retry = () => {
      void agents.refetch();
      void items.refetch();
    };
    return (
      <section aria-label={t("screen.dashboard")} data-screen="dashboard" className="dash">
        <Alerts agents={agentList} chainBroken={brokenSeq} headerOk={status.header_ok} m={m} />
        <ErrorState action={m("error.action")} error={failure.error} onRetry={retry} retrying={agents.isFetching || items.isFetching} />
      </section>
    );
  }

  const empty = agents.isSuccess && items.isSuccess && agentList.length === 0 && itemList.length === 0;
  if (empty) {
    return (
      <section aria-label={t("screen.dashboard")} data-screen="dashboard" className="dash">
        <Alerts agents={agentList} chainBroken={brokenSeq} headerOk={status.header_ok} m={m} />
        <EmptyState
          as="h2"
          gate
          title={m("empty.title")}
          body={m("empty.body")}
          action={localOnly ? undefined : <Button variant="ghost" icon="info" onClick={() => setConnectOpen(true)}>{m("empty.connect")}</Button>}
        />
        <div className="dash-empty">
          <ol className="steps" aria-label={m("empty.steps")}>
            <li><span className="grow">{m("empty.step.item")}</span><Button size="sm" variant="primary" onClick={() => navigate("~/editor/new")}>{m("empty.step.item.action")}</Button></li>
            {!localOnly && <li><span className="grow">{m("empty.step.agent")}</span><Button size="sm" onClick={() => navigate("~/agents?new=1")}>{m("empty.step.agent.action")}</Button></li>}
            <li><span className="grow">{m("empty.step.grant")}</span><Button size="sm" onClick={() => navigate("~/policies?new=1")}>{m("empty.step.grant.action")}</Button></li>
          </ol>
        </div>
        {core}
      </section>
    );
  }

  const activeAgents = agentList.filter((a) => a.status === "active").length;
  return (
    <section aria-label={t("screen.dashboard")} data-screen="dashboard" className="dash">
      <Alerts agents={agentList} chainBroken={brokenSeq} headerOk={status.header_ok} m={m} />
      <Band m={m} agents={activeAgents} waiting={requests.data?.length ?? 0} leases={leases.data?.length ?? 0} onConnect={localOnly ? null : () => setConnectOpen(true)} />
      <div className="cols c-main-side">
        {requests.isError ? (
          <Panel title={m("queue.title")} icon="bell"><PartError m={m} error={requests.error} onRetry={() => void requests.refetch()} /></Panel>
        ) : requests.isPending ? (
          <Panel title={m("queue.title")} icon="bell"><Skeleton label={m("loading")} rows={2} /></Panel>
        ) : (
          <Queue requests={requests.data} m={m} now={now} />
        )}
        <Health m={m} network={network} status={status} localOnly={localOnly} />
      </div>
      <div className="cols c-main-side">
        <Feed m={m} agents={agentList} items={itemList} />
        {leases.isError ? (
          <Panel title={m("expires.title")} icon="timer"><PartError m={m} error={leases.error} onRetry={() => void leases.refetch()} /></Panel>
        ) : (
          <Expires m={m} leases={leases.data ?? []} items={itemList} agents={agentList} now={now} />
        )}
      </div>
      {core}
    </section>
  );
}
