import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { OperatorPublic_Serialize } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useCountdown, formatLeft } from "../../state/time";
import { Button, ErrorState, errorText, Field, Icon, Notice, Skeleton } from "../../ui";
import { useOperators, useVaultStatus } from "../../ipc/queries";
import { Brand } from "./Brand";
import { messages } from "./messages";

const initials = (label: string) =>
  label
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");

/** The operator who unlocked most recently comes first, so the usual person has nothing to pick. */
export function sortOperators(list: readonly OperatorPublic_Serialize[]): OperatorPublic_Serialize[] {
  return [...list].sort((a, b) => (b.last_unlock_at ?? "").localeCompare(a.last_unlock_at ?? ""));
}

type Mode = "phrase" | "recovery";

/**
 * Unlock with an operator phrase or the recovery key. The phrase and the key are in local state only and are cleared
 * after every try, so a failed secret never stays in the page.
 */
export function UnlockForm() {
  const t = useScreenT(messages);
  const queryClient = useQueryClient();
  const operators = useOperators();
  const status = useVaultStatus();
  const [mode, setMode] = useState<Mode>("phrase");
  const [selected, setSelected] = useState<string | null>(null);
  const [phrase, setPhrase] = useState("");
  const [recovery, setRecovery] = useState("");
  const [busy, setBusy] = useState(false);
  const [opening, setOpening] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [failure, setFailure] = useState<UiError | null>(null);
  const phraseRef = useRef<HTMLInputElement>(null);
  const recoveryRef = useRef<HTMLTextAreaElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // The failed tries and the wait come from the backend (DEC-INT10-10), so a restart or a second window shows the same.
  const failedTries = status.data?.failed_unlocks ?? 0;
  const triesLeft = status.data?.free_unlock_tries_left ?? 0;
  const retryAfter = status.data?.retry_after_seconds ?? null;
  const until = retryAfter === null ? null : status.dataUpdatedAt + retryAfter * 1000;
  const lockReason = status.data?.last_lock_reason ?? null;

  const left = useCountdown(until);
  const waiting = until !== null && (left ?? 0) > 0;
  const waitedOut = until !== null && left === 0;
  useEffect(() => {
    if (waitedOut) (mode === "phrase" ? phraseRef : recoveryRef).current?.focus();
  }, [waitedOut, mode]);
  // The fields are disabled while the key is derived (the form stays in place, so nothing moves), which drops focus.
  const wasBusy = useRef(false);
  useEffect(() => {
    if (wasBusy.current && !busy && !opening) (mode === "phrase" ? phraseRef : recoveryRef).current?.focus();
    wasBusy.current = busy;
  }, [busy, opening, mode]);

  const list = sortOperators(operators.data ?? []);
  const operator = list.find((o) => o.id === selected) ?? list[0];

  const fail = async (error: UiError | null) => {
    setPhrase("");
    setRecovery("");
    setFailure(null);
    setProblem(null);
    const code = error?.code;
    if (code === "bad_credentials") {
      setProblem(mode === "phrase" ? t("phrase.problem", { name: operator?.label ?? "" }) : t("recovery.problem.wrong"));
    } else if (code === "validation_failed" && mode === "recovery") {
      setProblem(t("recovery.problem.format"));
    } else if (code !== "too_many_failures") {
      setFailure(error ?? { code: "ipc_unreachable", message: "", command: mode === "phrase" ? "vault_unlock" : "vault_unlock_recovery", retryAfterSeconds: null, fields: [] });
    }
    // Wait for the new tries count, so the status line goes straight from "Deriving" to the new count.
    await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    queueMicrotask(() => (mode === "phrase" ? phraseRef : recoveryRef).current?.focus());
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || waiting) return;
    const secret = mode === "phrase" ? phrase : recovery.trim();
    if (secret === "") {
      setProblem(mode === "phrase" ? t("phrase.problem.empty") : t("recovery.problem.empty"));
      return;
    }
    setBusy(true);
    setProblem(null);
    setFailure(null);
    // The secret leaves the fields (and the DOM) while the key is derived; it lives only in this call.
    setPhrase("");
    setRecovery("");
    try {
      if (mode === "phrase") {
        if (!operator) return;
        await ipc.vaultUnlock(operator.id, secret);
      } else {
        await ipc.vaultUnlockRecovery(secret);
      }
      setPhrase("");
      setRecovery("");
      setOpening(true);
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    } catch (error) {
      await fail(isIpcFailure(error) ? error.error : null);
    } finally {
      setBusy(false);
    }
  };

  if (operators.isPending) {
    return (
      <div className="unlock">
        <Brand mode="locked" title={t("title")} />
        <Skeleton label={t("operators.loading")} rows={2} />
      </div>
    );
  }
  if (operators.isError) {
    return (
      <div className="unlock">
        <ErrorState as="h1" action={t("operators.error")} error={operators.error} onRetry={() => void operators.refetch()} retrying={operators.isFetching} />
      </div>
    );
  }

  const kdfProblem = failure?.code === "unavailable";
  const triesText =
    failedTries === 0
      ? t("tries.none")
      : triesLeft === 0
        ? t("tries.wait", { n: failedTries })
        : t(failedTries === 1 ? "tries.one" : "tries.some", { n: failedTries, left: triesLeft });
  const isWait = waiting;

  return (
    <form className={opening ? "unlock opening" : "unlock"} noValidate aria-busy={busy || undefined} onSubmit={(e) => void submit(e)}>
      <Brand mode={opening ? "open" : busy ? "spin" : "locked"} title={isWait ? t("wait.title") : busy ? t("loading.title") : t("title")} headingRef={headingRef}>
        {opening ? (
          <p className="sub" role="status">{t("opening")}</p>
        ) : isWait ? (
          <p className="sub">{t("wait.body")}</p>
        ) : (
          <p className="sub">{t("sub")}</p>
        )}
      </Brand>
      {lockReason && !opening && (
        <p className="reason">
          <Icon name="lock" size={14} />
          {t(`reason.${lockReason}`)}
        </p>
      )}

      {isWait && (
        <div className="wait" role="timer" aria-live="off" aria-label={t("wait.timer")}>
          {formatLeft(left ?? 0)}
        </div>
      )}
      {waitedOut && !isWait && <Notice tone="ok" title={t("wait.over")} />}

      {kdfProblem && failure && (
        <Notice tone="bad" title={t("kdf.title")}>
          {t("kdf.body")} <span className="code block">{t("fail.line", { command: failure.command, code: failure.code })}</span>
        </Notice>
      )}
      {failure && !kdfProblem && (
        <Notice tone="bad" title={t("fail.title")}>
          {errorText(failure)} <span className="code block">{t("fail.line", { command: failure.command, code: failure.code })}</span>
        </Notice>
      )}

      {mode === "phrase" ? (
        <>
          {!isWait && list.length > 0 && (
            <fieldset className="ops">
              <legend>{t("who")}</legend>
              <div className="ops-list">
                {list.map((o) => (
                  <label className="op" key={o.id}>
                    <input type="radio" name="operator" value={o.id} checked={o.id === operator?.id} onChange={() => setSelected(o.id)} disabled={busy || opening} />
                    <span className="avatar" aria-hidden="true">{initials(o.label)}</span>
                    <span className="name">{o.label}</span>
                    <span className="role">{t(`role.${o.role}`)}</span>
                    <Icon name="check" size={16} className="tick" />
                  </label>
                ))}
              </div>
            </fieldset>
          )}
          <Field label={t("phrase.label")} {...(problem ? { problem } : {})}>
            {(control) => (
              <input
                {...control}
                ref={phraseRef}
                className="input lg mono"
                type="password"
                autoFocus
                autoComplete="current-password"
                spellCheck={false}
                disabled={isWait || opening || busy}
                aria-label={isWait ? t("wait.phrase.disabled") : undefined}
                value={phrase}
                onChange={(e) => {
                  setPhrase(e.target.value);
                  setProblem(null);
                }}
              />
            )}
          </Field>
        </>
      ) : (
        <Field label={t("recovery.label")} hint={t("recovery.hint")} {...(problem ? { problem } : {})}>
          {(control) => (
            <textarea
              {...control}
              ref={recoveryRef}
              className="input mono"
              rows={3}
              autoFocus
              autoComplete="off"
              spellCheck={false}
              placeholder={t("recovery.placeholder")}
              disabled={isWait || opening || busy}
              value={recovery}
              onChange={(e) => {
                setRecovery(e.target.value);
                setProblem(null);
              }}
            />
          )}
        </Field>
      )}

      <Button variant="primary" size="lg" type="submit" icon="unlock" loading={busy} disabled={isWait || opening} aria-disabled={isWait || opening}>
        {t("submit")}
      </Button>
      <div className="tries">
        {/* While the key is derived, this line says so, in the place of the tries (it is always a live region). */}
        <span role="status" className={failedTries > 0 && !busy ? "warn" : undefined}>
          {failedTries > 0 && !busy && <Icon name="alert" size={14} />}
          {busy ? t("loading.body") : triesText}
        </span>
        <Button
          size="sm"
          variant="ghost"
          disabled={opening || busy}
          onClick={() => {
            setMode(mode === "phrase" ? "recovery" : "phrase");
            setProblem(null);
            setFailure(null);
            setPhrase("");
            setRecovery("");
          }}
        >
          {mode === "phrase" ? t("recovery.use") : t("phrase.use")}
        </Button>
      </div>
    </form>
  );
}
