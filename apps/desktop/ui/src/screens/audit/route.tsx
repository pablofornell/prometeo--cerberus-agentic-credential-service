import { Fragment, useEffect, useState, type ReactNode } from "react";
import type { AuditEntryView_Serialize, ChainReportView_Serialize } from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { pickSavePath } from "../../ipc/dialogs";
import { useOperators } from "../../ipc/queries";
import { PageActions } from "../../shell/PageActions";
import {
  Button,
  EmptyState,
  ErrorState,
  errorText,
  GateMark,
  Icon,
  Input,
  Select,
  Skeleton,
  UntrustedText,
  useToast,
  type SelectOption,
} from "../../ui";
import { BREAK_TEXT, EVENT_TYPES, phraseFor } from "./catalog";
import { messages } from "./messages";
import {
  NO_FILTER,
  useAuditAgents,
  useAuditItems,
  useChain,
  useEvents,
  type AuditFilter,
  type Outcome,
  type Range,
} from "./queries";
import "./audit.css";

type M = ReturnType<typeof useScreenT<typeof messages>>;

const timeOf = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString([], { hour12: false });
};

const dayKey = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toDateString();
};

function dayLabel(iso: string, m: M): string {
  const d = new Date(iso);
  const date = d.toLocaleDateString([], { day: "numeric", month: "long" });
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return m("day.today", { date });
  const yesterday = new Date(today.getTime() - 86_400_000);
  if (d.toDateString() === yesterday.toDateString()) return m("day.yesterday", { date });
  return d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
}

interface Names {
  agent: (id: string | null) => string;
  operator: (id: string | null) => string;
  item: (id: string | null) => string | null;
}

function ChainCard({
  m,
  chain,
  lowestLoaded,
  onJump,
  jumping,
}: {
  m: M;
  chain: ReturnType<typeof useChain>;
  lowestLoaded: number | null;
  onJump: (seq: number) => void;
  jumping: boolean;
}) {
  const verifying = chain.isFetching;
  const report: ChainReportView_Serialize | undefined = chain.data;
  const verify = (
    <Button icon="refresh" onClick={() => void chain.refetch()} loading={verifying}>
      {m("chain.verify")}
    </Button>
  );

  if (chain.isPending || (verifying && !report)) {
    return (
      <section className="chain checking" aria-live="polite" aria-busy="true" aria-label={m("chain.checking")}>
        <span className="seal"><GateMark size={40} mode="spin" /></span>
        <div className="grow">
          <strong>{m("chain.checking")}</strong>
          <span className="small secondary">{m("chain.checkingSub")}</span>
        </div>
      </section>
    );
  }
  if (chain.isError && !report) {
    return (
      <section className="chain error" aria-live="polite">
        <span className="seal"><Icon name="alert" size={20} /></span>
        <div className="grow">
          <strong>{m("chain.error")}</strong>
          <span className="small secondary">{m("chain.errorSub")} {errorText(chain.error.error)}</span>
        </div>
        <div className="chain-acts">{verify}</div>
      </section>
    );
  }
  if (!report) return null;
  if (report.ok) {
    return (
      <section className="chain" aria-live="polite" aria-busy={verifying || undefined}>
        <span className="seal"><Icon name="checkCircle" size={20} /></span>
        <div className="grow">
          <strong>{m("chain.ok")}</strong>
          <span className="small secondary">
            {report.count === 0
              ? m("chain.okEmpty")
              : m("chain.okSub", {
                  count: report.count.toLocaleString(),
                  first: report.first_seq.toLocaleString(),
                  last: report.last_seq.toLocaleString(),
                  time: new Date(chain.dataUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false }),
                })}
          </span>
        </div>
        <div className="chain-acts">{verify}</div>
      </section>
    );
  }
  const seq = report.broken_seq ?? 0;
  const reason = (report.break_kind && BREAK_TEXT[report.break_kind]) || report.break_kind || "";
  const notLoaded = lowestLoaded !== null && seq < lowestLoaded;
  return (
    <section className="chain broken" aria-live="assertive" role="alert">
      <span className="seal"><Icon name="shieldAlert" size={20} /></span>
      <div className="grow">
        <strong>{m("chain.bad", { seq: seq.toLocaleString() })}</strong>
        <span className="small">{m("chain.badSub", { reason, seq: seq.toLocaleString() })}</span>
        {notLoaded && <span className="small">{m("chain.notLoaded", { seq: seq.toLocaleString() })}</span>}
      </div>
      <div className="chain-acts">
        {notLoaded && (
          <Button onClick={() => onJump(seq)} loading={jumping}>
            {m("chain.jump", { seq: seq.toLocaleString() })}
          </Button>
        )}
        {verify}
      </div>
    </section>
  );
}

function Details({ entry, m }: { entry: AuditEntryView_Serialize; m: M }) {
  const fromAgent = entry.actor_kind === "agent";
  const details = entry.details && typeof entry.details === "object" && !Array.isArray(entry.details) ? Object.entries(entry.details) : [];
  const show = (key: string, value: unknown) => {
    const text = typeof value === "string" ? value : JSON.stringify(value);
    // Text that an agent wrote, or any `reason`, is untrusted: it can hold instructions meant for a person or a model.
    return typeof value === "string" && (fromAgent || key === "reason") ? <UntrustedText text={text} /> : text;
  };
  return (
    <dl className="kv-list">
      <dt>{m("event.kv.seq")}</dt>
      <dd>#{entry.seq}</dd>
      <dt>{m("event.kv.time")}</dt>
      <dd>{entry.occurred_at}</dd>
      {entry.actor_id && (<><dt>{m("event.kv.actor")}</dt><dd>{entry.actor_kind}:{entry.actor_id}</dd></>)}
      {entry.target_kind && (<><dt>{m("event.kv.target")}</dt><dd>{entry.target_kind}{entry.target_id ? `:${entry.target_id}` : ""}</dd></>)}
      {entry.request_id && (<><dt>{m("event.kv.request")}</dt><dd>{entry.request_id}</dd></>)}
      {details.map(([key, value]) => (
        <Fragment key={key}>
          <dt>{key}</dt>
          <dd>{show(key, value)}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

function EventRow({ entry, m, names, breakSeq }: { entry: AuditEntryView_Serialize; m: M; names: Names; breakSeq: number | null }) {
  const [open, setOpen] = useState(false);
  const failed = entry.result !== "ok";
  const actor =
    entry.actor_kind === "agent" ? names.agent(entry.actor_id) : entry.actor_kind === "operator" ? names.operator(entry.actor_id) : m("event.system");
  const target = entry.target_kind === "item" ? names.item(entry.target_id) : null;
  const suspect = breakSeq !== null && entry.seq >= breakSeq;
  const here = breakSeq !== null && entry.seq === breakSeq;
  const icon = entry.actor_kind === "agent" ? "bot" : entry.actor_kind === "operator" ? "user" : "lock";
  const detailsId = `ev-${entry.seq}-details`;
  return (
    <li className={[suspect ? "suspect" : "", here ? "break-point" : ""].filter(Boolean).join(" ") || undefined} data-seq={entry.seq}>
      <time dateTime={entry.occurred_at}>{timeOf(entry.occurred_at)}</time>
      <span className={`node ${failed ? "bad" : entry.actor_kind}`}>
        <Icon name={failed ? "x" : icon} size={14} />
      </span>
      <div className="what">
        <span>
          <span className="actor">{actor}</span> {phraseFor(entry.event_type)}
          {target && <> <span className="target">{target}</span></>}
        </span>
        <span className="ev-row">
          <span className="ev">
            {entry.event_type},{" "}
            {failed ? <span className="fail">{m("event.result.fail", { code: entry.result })}</span> : m("event.result.ok")}
            {entry.request_id ? `, ${entry.request_id}` : ""}
          </span>
          <Button
            size="sm"
            variant="ghost"
            className="more"
            aria-expanded={open}
            aria-controls={detailsId}
            aria-label={`${open ? m("event.hide") : m("event.details")}: ${m("event.detailsFor", { seq: entry.seq })}`}
            onClick={() => setOpen(!open)}
          >
            <Icon name={open ? "chevD" : "chevR"} size={14} />
            {open ? m("event.hide") : m("event.details")}
          </Button>
        </span>
        {here && <span className="flag">{m("chain.here")}</span>}
        {suspect && !here && <span className="flag sr-only">{m("chain.suspect")}</span>}
        <div id={detailsId} hidden={!open}>
          {open && <Details entry={entry} m={m} />}
        </div>
      </div>
      <span className="seq">#{entry.seq}</span>
    </li>
  );
}

function ExportAction({ m }: { m: M }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      const dest = await pickSavePath("cerberus-audit.jsonl");
      if (dest === null) return;
      const n = await ipc.auditExport(dest);
      toast.push({ tone: "success", title: m("export.done", { n: n.toLocaleString() }) });
    } catch (error) {
      toast.push({ tone: "error", title: m("export.fail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    } finally {
      setBusy(false);
    }
  };
  return (
    <PageActions>
      <Button icon="download" loading={busy} onClick={() => void run()}>
        {m("export.button")}
      </Button>
    </PageActions>
  );
}

/** The search box waits this long after the last key before it asks the backend. */
const SEARCH_DELAY_MS = 300;

export default function AuditScreen() {
  const m = useScreenT(messages);
  const [filter, setFilter] = useState<AuditFilter>(NO_FILTER);
  // The search box has its own state: the query goes out when the person stops typing.
  const [search, setSearch] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setFilter((f) => (f.text === search ? f : { ...f, text: search })), SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [search]);
  const [jumping, setJumping] = useState(false);
  const chain = useChain();
  const events = useEvents(filter);
  const agents = useAuditAgents();
  const operators = useOperators();
  const items = useAuditItems();

  const names: Names = {
    agent: (id) => agents.data?.find((a) => a.id === id)?.name ?? m("event.agent"),
    operator: (id) => operators.data?.find((o) => o.id === id)?.label ?? m("event.operator"),
    item: (id) => (id ? (items.data?.find((i) => i.id === id)?.title ?? null) : null),
  };

  const all = events.data?.pages.flat() ?? [];
  const lowestLoaded = all.length ? Math.min(...all.map((e) => e.seq)) : null;
  const breakSeq = chain.data && !chain.data.ok ? (chain.data.broken_seq ?? null) : null;
  const filtered = filter.eventType !== "" || filter.agentId !== "" || filter.range !== "all" || filter.outcome !== "all" || filter.text.trim() !== "";

  const jump = async (seq: number) => {
    setJumping(true);
    try {
      let low = lowestLoaded ?? Infinity;
      let more = events.hasNextPage;
      for (let guard = 0; more && low > seq && guard < 100; guard += 1) {
        const next = await events.fetchNextPage();
        const rows = next.data?.pages.flat() ?? [];
        low = rows.length ? Math.min(...rows.map((e) => e.seq)) : low;
        more = next.hasNextPage;
      }
    } finally {
      setJumping(false);
      requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-seq="${seq}"]`)?.scrollIntoView({ block: "center" }));
    }
  };

  const rangeOptions: SelectOption[] = (["day", "week", "month", "all"] as Range[]).map((r) => ({ value: r, label: m(`range.${r}`) }));
  const typeOptions: SelectOption[] = [{ value: "", label: m("type.all") }, ...EVENT_TYPES.map((type) => ({ value: type, label: type }))];
  const agentOptions: SelectOption[] = [{ value: "", label: m("agent.all") }, ...(agents.data ?? []).map((a) => ({ value: a.id, label: a.name }))];
  const outcomeOptions: SelectOption[] = (["all", "ok", "failed"] as Outcome[]).map((o) => ({ value: o, label: m(`outcome.${o}`) }));
  const clear = () => {
    setSearch("");
    setFilter(NO_FILTER);
  };

  const list = () => {
    if (events.isPending) return <Skeleton label={m("loading.events")} rows={5} />;
    if (events.isError) return <ErrorState action={m("error.action")} error={events.error} onRetry={() => void events.refetch()} retrying={events.isFetching} />;
    if (all.length === 0) {
      if (!filtered && !events.hasNextPage) return <EmptyState icon="audit" title={m("emptyLog.title")} body={m("emptyLog.body")} />;
      return (
        <EmptyState
          icon="search"
          title={m("empty.title")}
          body={m("empty.body")}
          action={<Button onClick={clear}>{m("filters.clear")}</Button>}
        />
      );
    }
    const out: ReactNode[] = [];
    let lastDay = "";
    let group: ReactNode[] = [];
    const flush = (day: string, label: string) => {
      if (!group.length) return;
      out.push(
        <div key={day + label} role="group" aria-label={label}>
          <h2 className="day">{label}</h2>
          <ol className="tl">{group}</ol>
        </div>,
      );
      group = [];
    };
    let lastLabel = "";
    for (const entry of all) {
      const key = dayKey(entry.occurred_at);
      if (key !== lastDay) {
        flush(lastDay, lastLabel);
        lastDay = key;
        lastLabel = dayLabel(entry.occurred_at, m);
      }
      group.push(<EventRow key={entry.seq} entry={entry} m={m} names={names} breakSeq={breakSeq} />);
    }
    flush(lastDay, lastLabel);
    return (
      <>
        <div aria-label={m("events.label")} role="region">
          {out}
        </div>
        <div className="more-row">
          {events.hasNextPage ? (
            <Button onClick={() => void events.fetchNextPage()} loading={events.isFetchingNextPage}>
              {m("events.older")}
            </Button>
          ) : (
            <span className="small muted">{m("events.end")}</span>
          )}
        </div>
      </>
    );
  };

  return (
    <section className="audit" data-screen="audit" aria-label={t("screen.audit")}>
      <ExportAction m={m} />
      <ChainCard m={m} chain={chain} lowestLoaded={lowestLoaded} onJump={(seq) => void jump(seq)} jumping={jumping} />
      <div className="filters" role="search" aria-label={m("filters.label")}>
        <label className="sr-only" htmlFor="audit-range">{m("filters.time")}</label>
        <Select id="audit-range" options={rangeOptions} value={filter.range} onChange={(e) => setFilter({ ...filter, range: e.target.value as Range })} />
        <label className="sr-only" htmlFor="audit-type">{m("filters.type")}</label>
        <Select id="audit-type" options={typeOptions} value={filter.eventType} onChange={(e) => setFilter({ ...filter, eventType: e.target.value })} />
        <label className="sr-only" htmlFor="audit-agent">{m("filters.agent")}</label>
        <Select id="audit-agent" options={agentOptions} value={filter.agentId} onChange={(e) => setFilter({ ...filter, agentId: e.target.value })} />
        <label className="sr-only" htmlFor="audit-outcome">{m("filters.outcome")}</label>
        <Select id="audit-outcome" options={outcomeOptions} value={filter.outcome} onChange={(e) => setFilter({ ...filter, outcome: e.target.value as Outcome })} />
        <label className="sr-only" htmlFor="audit-text">{m("filters.text")}</label>
        <Input id="audit-text" type="search" maxLength={200} autoComplete="off" spellCheck={false} placeholder={m("filters.text.placeholder")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <Button size="sm" variant="ghost" icon="refresh" onClick={() => void events.refetch()} loading={events.isRefetching}>
          {m("filters.refresh")}
        </Button>
        {filtered && (
          <Button size="sm" variant="ghost" onClick={clear}>
            {m("filters.clear")}
          </Button>
        )}
      </div>
      <p className="small muted">{m("filters.note")}</p>
      {list()}
    </section>
  );
}
