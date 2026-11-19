import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "wouter";
import type { AccessRequestView_Serialize, ApprovalOption } from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { ipc, isIpcFailure, isLockError } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { usePendingRequests, useVaultStatus } from "../../ipc/queries";
import { windowLabel } from "../../shell/windowLabel";
import { useCan } from "../../state/session";
import { Button, EmptyState, ErrorState, GateMark, Notice, Skeleton, errorText, useToast } from "../../ui";
import { ApprovalCard, HOLD_MS, type Choice } from "./ApprovalCard";
import { messages } from "./messages";
import "./approval.css";

type S = ReturnType<typeof useScreenT<typeof messages>>;

interface Outcome {
  tone: "done" | "ended" | "failed";
  title: string;
  body: string;
  code?: string;
}

const KEYS: Record<string, ApprovalOption> = { a: "once", f: "minutes_15", s: "session" };

/** A, F, S need a 0.6 s hold; D denies at once. Only the approval window listens (shortcut table in the IA). */
function useDecisionKeys(active: boolean, onDecide: (choice: Choice) => void): ApprovalOption | null {
  const [held, setHeld] = useState<ApprovalOption | null>(null);
  // The latest handler, so a re-render never restarts a hold in progress.
  const latest = useRef(onDecide);
  useEffect(() => {
    latest.current = onDecide;
  });
  useEffect(() => {
    if (!active) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const stop = () => {
      if (timer) clearTimeout(timer);
      timer = null;
      setHeld(null);
    };
    const down = (e: KeyboardEvent) => {
      if (e.repeat || e.ctrlKey || e.metaKey || e.altKey) return;
      const key = e.key.toLowerCase();
      if (key === "d") {
        e.preventDefault();
        latest.current("deny");
        return;
      }
      const option = KEYS[key];
      if (!option || timer) return;
      setHeld(option);
      timer = setTimeout(() => {
        timer = null;
        setHeld(null);
        latest.current(option);
      }, HOLD_MS);
    };
    window.addEventListener("keydown", down);
    window.addEventListener("keyup", stop);
    window.addEventListener("blur", stop);
    return () => {
      window.removeEventListener("keydown", down);
      window.removeEventListener("keyup", stop);
      window.removeEventListener("blur", stop);
      stop();
    };
  }, [active]);
  return held;
}

function outcomeFor(choice: Choice, request: AccessRequestView_Serialize, s: S): Outcome {
  const vars = { agent: request.agent_name, item: request.item_title };
  return choice === "deny"
    ? { tone: "done", title: s("done.deny"), body: s("done.deny.body", vars) }
    : { tone: "done", title: s(`done.${choice}`), body: s(`done.${choice}.body`, vars) };
}

/** Screen 8: the approval prompt (own small window at `#approval`) and the queue page in the main window. */
export default function ApprovalScreen() {
  const s = useScreenT(messages);
  const inWindow = windowLabel() === "approval";
  const status = useVaultStatus();
  const pending = usePendingRequests();
  const canDecide = useCan("operator");
  const queryClient = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [reviewId, setReviewId] = useState<string | null>(null);

  const requests = useMemo(
    () => [...(pending.data ?? [])].sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at)),
    [pending.data],
  );
  const burstAgent = requests.find((r) => r.burst_warning && requests.filter((o) => o.agent_id === r.agent_id).length > 1)?.agent_id ?? null;
  const burst = burstAgent ? requests.filter((r) => r.agent_id === burstAgent) : [];
  const current = requests.find((r) => r.id === reviewId) ?? (inWindow && burst.length > 1 ? null : requests[0]) ?? null;

  const refresh = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.requests.all() }),
      queryClient.invalidateQueries({ queryKey: qk.leases.all() }),
    ]);
  }, [queryClient]);

  const report = useCallback(
    (next: Outcome) => {
      if (inWindow) setOutcome(next);
      else toast.push({ tone: next.tone === "done" ? "success" : "error", title: next.title, detail: next.body || undefined });
    },
    [inWindow, toast],
  );

  const decide = useCallback(
    async (request: AccessRequestView_Serialize, choice: Choice) => {
      setBusy(true);
      try {
        if (choice === "deny") await ipc.requestDeny(request.id);
        else await ipc.requestApprove(request.id, choice);
        setReviewId(null);
        report(outcomeFor(choice, request, s));
      } catch (error) {
        if (isIpcFailure(error) && (error.code === "conflict" || error.code === "not_found")) {
          setReviewId(null);
          report({ tone: "ended", title: s("ended.title"), body: s("ended.body"), code: `${error.error.command}: ${error.code}` });
        } else {
          report({
            tone: "failed",
            title: s("failed.title"),
            body: isIpcFailure(error) ? errorText(error.error) : "",
            code: isIpcFailure(error) ? `${error.error.command}: ${error.code}` : undefined,
          });
        }
      } finally {
        setBusy(false);
        await refresh();
      }
    },
    [refresh, report, s],
  );

  const denyAll = async (list: readonly AccessRequestView_Serialize[]) => {
    setBusy(true);
    try {
      await Promise.all(list.map((r) => ipc.requestDeny(r.id)));
      report({ tone: "done", title: s("done.denyAll", { n: list.length }), body: "" });
    } catch (error) {
      report({ tone: "failed", title: s("failed.title"), body: isIpcFailure(error) ? errorText(error.error) : "" });
    } finally {
      setBusy(false);
      await refresh();
    }
  };

  const suspend = async (agentId: string, name: string) => {
    try {
      await ipc.agentSetStatus(agentId, "suspended");
      toast.push({ tone: "success", title: s("done.suspended", { agent: name }) });
    } catch (error) {
      toast.push({ tone: "error", title: s("failed.title"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    }
  };

  const keysActive = inWindow && canDecide && !busy && current !== null && outcome === null;
  const onKey = useCallback(
    (choice: Choice) => {
      if (current) void decide(current, choice);
    },
    [current, decide],
  );
  const held = useDecisionKeys(keysActive, onKey);

  const locked = status.data !== undefined && status.data.state !== "unlocked";
  const body = (() => {
    if (locked || (pending.isError && isLockError(pending.error))) {
      return (
        <div className="ap-result" role="status">
          <GateMark size={48} mode="locked" />
          <h1>{s("locked.title")}</h1>
          <p className="secondary">{s("locked.body")}</p>
          {!inWindow && (
            <Link className="btn primary" href="~/unlock">
              {t("locked.unlock")}
            </Link>
          )}
        </div>
      );
    }
    if (pending.isPending) return <Skeleton label={s("load.label")} variant="block" />;
    if (pending.isError) {
      return <ErrorState as={inWindow ? "h1" : "h2"} action={s("load.action")} error={pending.error} onRetry={() => void pending.refetch()} retrying={pending.isFetching} />;
    }
    if (outcome && inWindow) {
      return (
        <div className="ap-result" role={outcome.tone === "done" ? "status" : "alert"}>
          <GateMark size={48} mode={outcome.tone === "done" ? "open" : "locked"} />
          <h1>{outcome.title}</h1>
          {outcome.body && <p className="secondary">{outcome.body}</p>}
          {outcome.code && <span className="code">{outcome.code}</span>}
          <div className="row-inline">
            {requests.length > 0 && (
              <Button variant="primary" onClick={() => setOutcome(null)}>
                {s("done.next")}
              </Button>
            )}
          </div>
        </div>
      );
    }
    if (requests.length === 0) {
      return (
        <EmptyState
          as={inWindow ? "h1" : "h2"}
          gate
          title={t("empty.approval.title")}
          body={inWindow ? s("empty.window") : t("empty.approval.body")}
        />
      );
    }
    if (inWindow && !current && burst.length > 1) {
      const name = burst[0]?.agent_name ?? "";
      return (
        <section className="ap-card ap-burst" aria-labelledby="ap-burst-h">
          <Notice tone="warn" title={s("burst.single", { agent: name })} />
          <h1 id="ap-burst-h" className="ap-title">{s("burst.title", { n: burst.length, agent: name })}</h1>
          <ul aria-label={s("burst.list")}>
            {burst.map((r) => (
              <li key={r.id}>
                <span className="grow">{r.item_title}</span>
                <span className={`env ${r.environment}`}>{r.environment}</span>
                {canDecide && (
                  <Button size="sm" aria-label={s("burst.review.label", { item: r.item_title })} onClick={() => setReviewId(r.id)}>
                    {s("burst.review")}
                  </Button>
                )}
              </li>
            ))}
          </ul>
          {canDecide && (
            <Button variant="danger" icon="x" disabled={busy} onClick={() => void denyAll(burst)}>
              {s("burst.denyAll", { n: burst.length })}
            </Button>
          )}
        </section>
      );
    }
    if (inWindow) {
      return current ? (
        <ApprovalCard request={current} canDecide={canDecide} busy={busy} held={held} onDecide={(c) => void decide(current, c)} heading="h1" focusDeny />
      ) : null;
    }
    return (
      <div className="ap-list">
        {burst.length > 1 && canDecide && (
          <Notice
            tone="warn"
            title={s("burst.title", { n: burst.length, agent: burst[0]?.agent_name ?? "" })}
            actions={
              <>
                <Button size="sm" variant="danger" icon="x" disabled={busy} onClick={() => void denyAll(burst)}>
                  {s("burst.denyAll", { n: burst.length })}
                </Button>
                <Button size="sm" icon="lock" onClick={() => void suspend(burst[0]?.agent_id ?? "", burst[0]?.agent_name ?? "")}>
                  {s("burst.suspend", { agent: burst[0]?.agent_name ?? "" })}
                </Button>
              </>
            }
          />
        )}
        {requests.map((r) => (
          <ApprovalCard key={r.id} request={r} canDecide={canDecide} busy={busy} held={null} onDecide={(c) => void decide(r, c)} heading="h2" focusDeny={false} />
        ))}
      </div>
    );
  })();

  return (
    <section aria-label={s("window.title")} data-screen="approval" className="ap">
      {inWindow && (
        <div className="ap-head">
          <GateMark size={18} mode="open" />
          <span className="grow">{s("window.title")}</span>
          {requests.length > 0 && <span className="num">{s("window.count", { n: requests.length })}</span>}
        </div>
      )}
      {body}
    </section>
  );
}
