import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { RemoteSetupCheckView } from "../bindings";
import { useScreenT } from "../i18n";
import { ipc, isIpcFailure, toUiError, type UiError } from "../ipc/client";
import { qk } from "../ipc/keys";
import { RecoveryProof } from "../screens/create/RecoveryStep";
import { usePhraseGenerator, useStrength } from "../screens/create/hooks";
import { PhraseFields, phraseReady } from "../screens/create/Steps";
import { SETUP_FLOW_IDLE, setupFlowStore } from "../shell/setupFlow";
import { Button, Dialog, errorText, Field, GateMark, Icon, Input, Notice, Textarea, useToast } from "../ui";
import { messages } from "./messages";
import { checkProblem, createProblem, problemOf } from "./setupProblems";
import "../screens/create/create.css";
import "../screens/create/recovery.css";
import "./remote.css";

type Phase = "code" | "owner" | "creating" | "recovery";
type Check = { status: "idle" } | { status: "checking" } | { status: "done"; view: RemoteSetupCheckView } | { status: "failed"; error: UiError };

const NAME_MAX = 64;
const PHRASE_WORDS = 7;
const STEPS = [
  { phase: "code", label: "setup.step.server" },
  { phase: "owner", label: "setup.step.owner" },
  { phase: "recovery", label: "setup.step.recovery" },
] as const;

const failureOf = (failure: unknown, command: string): UiError =>
  isIpcFailure(failure) ? failure.error : { code: "ipc_unreachable", message: "", command, retryAfterSeconds: null, fields: [] };

/**
 * Set up a new server (ADR-0034, DEC-SRV-3): the server runs cerberusd with no vault and waits for its first client.
 * The person pastes the setup code of the server, checks that it answers, chooses a name and a master phrase, and the
 * server makes the vault. Then the recovery key is shown once and checked, and the desktop connects in remote mode.
 *
 * `App` mounts the one dialog and `setupFlowStore` says when it is open (`openSetupDialog`). The long call and the
 * answer with the recovery key are kept in that store, so they survive the screen that started the flow. The backend
 * holds the key and the admin bundle as soon as the server answers, and the key always reaches this dialog, even when
 * this computer could not store the profile: then the person saves it again from here. The code and the phrase are
 * cleared as soon as they are not needed.
 */
export function SetupServerDialog() {
  const t = useScreenT(messages);
  const queryClient = useQueryClient();
  const toast = useToast();
  const flow = setupFlowStore.use();
  const { open, lockFirst, creating, made } = flow;
  const [step, setStep] = useState<"code" | "owner">("code");
  const phase: Phase = made ? "recovery" : creating ? "creating" : step;
  const setPhase = (next: "code" | "owner") => setStep(next);
  const [code, setCode] = useState("");
  const [url, setUrl] = useState("");
  const [check, setCheck] = useState<Check>({ status: "idle" });
  const [owner, setOwner] = useState("");
  const [device, setDevice] = useState("");
  const [phrase, setPhrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const [failure, setFailure] = useState<UiError | null>(null);
  // A wait that the server asks for after too many wrong codes (`too_many_failures`): the time it ends and the clock.
  const [waitUntil, setWaitUntil] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [connecting, setConnecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [connectError, setConnectError] = useState<UiError | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const checkRun = useRef(0);

  const generator = usePhraseGenerator(PHRASE_WORDS, (text) => {
    setPhrase(text);
    setConfirm(text);
  });
  const strength = useStrength(open && phase === "owner" ? phrase : "", [owner]);

  // The step heading takes focus when the step changes, so a screen reader starts at the new step.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (phase === "recovery" || phase === "creating") heading.current?.focus();
  }, [phase]);

  const waitLeft = waitUntil === null ? 0 : Math.max(0, Math.ceil((waitUntil - now) / 1000));
  const ticking = waitUntil !== null && waitLeft > 0;
  useEffect(() => {
    if (!ticking) return;
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [ticking]);

  const busy = creating || connecting || saving;
  const keepOpen = phase === "creating" || phase === "recovery";

  const reset = () => {
    checkRun.current += 1;
    setStep("code");
    setCode("");
    setUrl("");
    setCheck({ status: "idle" });
    setOwner("");
    setDevice("");
    setPhrase("");
    setConfirm("");
    setTouched(false);
    setFailure(null);
    setWaitUntil(null);
    setConnecting(false);
    setSaving(false);
    setConnectError(null);
    generator.forget();
    setupFlowStore.set(SETUP_FLOW_IDLE);
  };

  const close = () => {
    if (keepOpen) return;
    reset();
    void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
  };

  const verified = check.status === "done" && check.view.state === "pending";

  const runCheck = async () => {
    const run = ++checkRun.current;
    setCheck({ status: "checking" });
    try {
      const view = await ipc.remoteSetupCheck(code.trim(), url.trim() || null);
      if (run === checkRun.current) setCheck({ status: "done", view });
    } catch (error) {
      if (run === checkRun.current) setCheck({ status: "failed", error: failureOf(error, "remote_setup_check") });
    }
  };

  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    if (code.trim() === "" || check.status === "checking") return;
    if (verified) setPhase("owner");
    else void runCheck();
  };

  const editCode = (next: { code?: string; url?: string }) => {
    checkRun.current += 1;
    if (next.code !== undefined) setCode(next.code);
    if (next.url !== undefined) setUrl(next.url);
    setCheck({ status: "idle" });
  };

  /** A code that cannot work again: back to the first step with nothing pasted. */
  const anotherCode = () => {
    editCode({ code: "" });
    setFailure(null);
    setWaitUntil(null);
    setPhase("code");
  };

  const trimmed = owner.trim();
  const ownerProblem = trimmed === "" ? t("setup.owner.problem.empty") : trimmed.length > NAME_MAX ? t("setup.owner.problem.long") : undefined;
  const deviceProblem = device.trim().length > NAME_MAX ? t("setup.device.problem.long") : undefined;
  const ready = phraseReady(phrase, confirm, strength);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (ownerProblem || deviceProblem || !ready || phase !== "owner") return;
    setFailure(null);
    setWaitUntil(null);
    setupFlowStore.set((f) => ({ ...f, creating: true }));
    try {
      const result = await ipc.remoteSetup(code.trim(), trimmed, phrase, device.trim() || null, url.trim() || null);
      // The store, not this component, keeps the answer: the dialog may have been closed or its screen left meanwhile.
      setupFlowStore.set((f) => ({
        ...f,
        creating: false,
        made: { key: result.recovery_key, profile: result.profile, storeError: result.store_error ? toUiError("remote_setup", result.store_error) : null },
      }));
      setPhrase("");
      setConfirm("");
      setCode("");
      generator.forget();
    } catch (error) {
      setupFlowStore.set((f) => ({ ...f, creating: false }));
      const ui = failureOf(error, "remote_setup");
      setFailure(ui);
      if (ui.code === "too_many_failures" && ui.retryAfterSeconds !== null) {
        const at = Date.now();
        setNow(at);
        setWaitUntil(at + ui.retryAfterSeconds * 1000);
      }
      setPhase("owner");
    }
  };

  const connect = async () => {
    if (!made?.profile) return;
    setConnecting(true);
    setConnectError(null);
    try {
      // The profile is stored already. The backend checks the switch, locks the local vault when `lockFirst` is set,
      // and restarts the app.
      await ipc.remoteActivate(made.profile.id, lockFirst);
      await ipc.remoteSetupFinish().catch(() => undefined);
      reset();
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
      await queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
    } catch (error) {
      const ui = failureOf(error, "remote_activate");
      setConnectError(ui);
      setConnecting(false);
      toast.push({ tone: "error", title: t("setup.connect.failed"), detail: errorText(ui) });
    }
  };

  /** The profile was not stored: try again from the bundle that the backend holds. */
  const save = async () => {
    setSaving(true);
    setConnectError(null);
    try {
      const profile = await ipc.remoteSetupSave();
      setupFlowStore.set((f) => (f.made ? { ...f, made: { ...f.made, profile, storeError: null } } : f));
      void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
    } catch (error) {
      const ui = failureOf(error, "remote_setup_save");
      setupFlowStore.set((f) => (f.made ? { ...f, made: { ...f.made, storeError: ui } } : f));
    } finally {
      setSaving(false);
    }
  };

  /** Done with the key. The stored profile stays: Settings connects to it. */
  const later = async () => {
    await ipc.remoteSetupFinish().catch(() => undefined);
    reset();
    void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
  };

  const codeProblem = problemOf(check.status === "failed" ? check.error : null, "code") ? t("setup.code.problem") : undefined;
  const urlProblem = problemOf(check.status === "failed" ? check.error : null, "url") ? t("setup.url.problem") : undefined;
  const fieldlessCheckError = check.status === "failed" && !codeProblem && !urlProblem ? check.error : null;

  let footer;
  let body;
  if (phase === "code") {
    footer = (
      <>
        <Button onClick={close}>{t("setup.cancel")}</Button>
        <Button variant="primary" type="submit" form="setup-code-form" icon={verified ? undefined : "server"} loading={check.status === "checking"} disabled={code.trim() === ""}>
          {verified ? t("setup.continue") : check.status === "idle" ? t("setup.check") : t("setup.check.again")}
        </Button>
      </>
    );
    body = (
      <form id="setup-code-form" className="setup-pane" noValidate onSubmit={submitCode}>
        <h3 ref={heading} tabIndex={-1}>{t("setup.code.h")}</h3>
        <p className="setup-lede">{t("setup.code.lede")}</p>
        <Field label={t("setup.code.label")} hint={t("setup.code.hint")} {...(codeProblem ? { problem: codeProblem } : {})}>
          {(control) => (
            <Textarea
              {...control}
              mono
              rows={3}
              className="setup-code"
              autoFocus
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              value={code}
              placeholder="cerberus-setup:1:…"
              onChange={(e) => editCode({ code: e.target.value })}
            />
          )}
        </Field>
        <details>
          <summary className="secondary">{t("setup.url.summary")}</summary>
          <div className="stack setup-more">
            <p className="small muted">{t("setup.url.body")}</p>
            <Field label={t("setup.url.label")} hint={t("setup.url.hint")} {...(urlProblem ? { problem: urlProblem } : {})}>
              {(control) => <Input {...control} mono autoComplete="off" spellCheck={false} value={url} onChange={(e) => editCode({ url: e.target.value })} />}
            </Field>
          </div>
        </details>
        <div className="setup-result" aria-live="polite">
          {check.status === "checking" && (
            <p className="setup-checking" role="status">
              <span className="spinner" aria-hidden="true" />
              {t("setup.check")}
            </p>
          )}
          {check.status === "done" && check.view.state === "pending" && (
            <>
              <Notice tone="ok" title={t("setup.found.title")}>
                {t("setup.found.body")}
              </Notice>
              <dl className="remote-facts">
                <dt>{t("fact.url")}</dt>
                <dd className="mono">{check.view.url}</dd>
                <dt>{t("setup.status")}</dt>
                <dd>{t("setup.status.pending")}</dd>
                <dt>{t("fact.version")}</dt>
                <dd className="mono">{check.view.version}</dd>
              </dl>
            </>
          )}
          {check.status === "done" && check.view.state === "locked_out" && (
            <Notice tone="warn" title={t("setup.locked.title")}>
              {t("setup.locked.body")}
            </Notice>
          )}
          {fieldlessCheckError && (
            <Notice tone="bad" title={checkProblem(fieldlessCheckError, t).title}>
              {checkProblem(fieldlessCheckError, t).body}
              <span className="code block">{t("setup.fail.line", { command: fieldlessCheckError.command, code: fieldlessCheckError.code })}</span>
            </Notice>
          )}
        </div>
      </form>
    );
  } else if (phase === "owner" || phase === "creating") {
    const problem = failure ? createProblem(failure, t) : null;
    footer = (
      <>
        <Button disabled={creating} onClick={() => setPhase("code")}>
          {t("setup.back")}
        </Button>
        <Button variant="primary" type="submit" form="setup-owner-form" icon="shield" loading={creating} disabled={creating || !ready || ticking}>
          {t("setup.create")}
        </Button>
      </>
    );
    body = creating ? (
      <div className="setup-pane setup-working" role="status" aria-busy="true">
        <GateMark size={48} mode="spin" />
        <h3 ref={heading} tabIndex={-1}>{t("setup.creating.title")}</h3>
        <ul className="progress-list">
          <li><span className="status warn" />{t("setup.creating.step1")}</li>
          <li><span className="status warn" />{t("setup.creating.step2")}</li>
          <li><span className="status warn" />{t("setup.creating.step3")}</li>
        </ul>
        <p className="small muted">{t("setup.creating.note")}</p>
      </div>
    ) : (
      <form id="setup-owner-form" className="setup-pane" noValidate onSubmit={(e) => void create(e)}>
        <h3 tabIndex={-1}>{t("setup.owner.h")}</h3>
        <p className="setup-lede">{t("setup.owner.lede")}</p>
        {problem && (
          <Notice
            tone="bad"
            title={problem.title}
            actions={
              problem.newCode ? (
                <Button size="sm" onClick={anotherCode}>
                  {t("setup.fail.again")}
                </Button>
              ) : undefined
            }
          >
            {problem.body}
            {failure && failure.code === "validation_failed" && failure.fields.length > 0 && (
              <ul className="problem-list" aria-label={t("setup.fail.fields")}>
                {failure.fields.map((f, i) => (
                  <li key={i}>
                    <code>{f.field}</code> {f.problem}
                  </li>
                ))}
              </ul>
            )}
            {waitUntil !== null && (
              <>
                <span className="sr-only">{t("setup.fail.wait.sr", { n: failure?.retryAfterSeconds ?? 0 })}</span>
                {/* The count is for the eyes only: a live region that changes each second would be read out each second. */}
                <span className="setup-wait block" aria-hidden="true">{ticking ? t("setup.fail.wait", { n: waitLeft }) : t("setup.fail.wait.over")}</span>
              </>
            )}
            {failure && <span className="code block">{t("setup.fail.line", { command: failure.command, code: failure.code })}</span>}
          </Notice>
        )}
        <p className="small muted setup-target">{t("setup.owner.server", { url: check.status === "done" ? check.view.url : "" })}</p>
        <Field label={t("setup.owner.label")} hint={t("setup.owner.hint")} {...(touched && ownerProblem ? { problem: ownerProblem } : {})}>
          {(control) => <Input {...control} large autoFocus autoComplete="name" value={owner} maxLength={NAME_MAX + 16} onChange={(e) => setOwner(e.target.value)} />}
        </Field>
        <PhraseFields
          autoFocus={false}
          phrase={phrase}
          confirm={confirm}
          onPhrase={(value) => {
            setPhrase(value);
            generator.forget();
          }}
          onConfirm={setConfirm}
          strength={strength}
          generated={generator.words}
          generating={generator.generating}
          generateFailed={generator.failed}
          onGenerate={generator.generate}
        />
        <details>
          <summary className="secondary">{t("setup.device.summary")}</summary>
          <div className="stack setup-more">
            <p className="small muted">{t("setup.device.body")}</p>
            <Field label={t("setup.device.label")} {...(touched && deviceProblem ? { problem: deviceProblem } : {})}>
              {(control) => <Input {...control} placeholder="desktop" autoComplete="off" value={device} onChange={(e) => setDevice(e.target.value)} />}
            </Field>
          </div>
        </details>
        <p className="small muted">{t("setup.next")}</p>
      </form>
    );
  } else {
    footer = undefined;
    body = (
      <section className="setup-pane" aria-labelledby="setup-recovery-h">
        <h3 id="setup-recovery-h" ref={heading} tabIndex={-1} className="print-keep">
          {t("setup.recovery.h")}
        </h3>
        <p className="setup-lede">{t("setup.recovery.lede")}</p>
        {made && made.profile === null && (
          <Notice tone="warn" title={t("setup.store.title")}>
            {t("setup.store.body")} {made.storeError ? errorText(made.storeError) : ""}
            {made.storeError && <span className="code block">{t("setup.fail.line", { command: made.storeError.command, code: made.storeError.code })}</span>}
          </Notice>
        )}
        {made && (
          <RecoveryProof
            recoveryKey={made.key}
            copy={() => ipc.remoteSetupCopyKey()}
            action={
              made.profile
                ? { label: t("setup.connect"), icon: "plug", loading: connecting, onRun: () => void connect() }
                : { label: t("setup.save"), icon: "download", loading: saving, onRun: () => void save() }
            }
            secondary={{ label: made.profile ? t("setup.later") : t("setup.later.unsaved"), onRun: () => void later() }}
          />
        )}
        {made?.profile && (
          <p className="small muted">
            {t("setup.recovery.saved")} {t("setup.connect.restart")}
          </p>
        )}
        {connectError && (
          <Notice tone="bad" title={t("setup.connect.failed")}>
            {errorText(connectError)} <span className="code block">{t("setup.fail.line", { command: connectError.command, code: connectError.code })}</span>
          </Notice>
        )}
      </section>
    );
  }

  const stepIndex = phase === "code" ? 0 : phase === "recovery" ? 2 : 1;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !next && close()}
      title={t("setup.title")}
      description={t("setup.desc")}
      dismissible={!keepOpen}
      wide
      footer={footer}
    >
      <div className="create-screen setup-server" aria-busy={busy || undefined}>
        <ol className="setup-steps" aria-label={t("setup.steps.label")}>
          {STEPS.map((step, i) => (
            <li key={step.phase} aria-current={i === stepIndex ? "step" : undefined} className={i < stepIndex ? "done" : i === stepIndex ? "now" : ""}>
              <span className="n" aria-hidden="true">{i < stepIndex ? <Icon name="check" size={13} /> : i + 1}</span>
              {t(step.label)}
            </li>
          ))}
        </ol>
        {body}
      </div>
    </Dialog>
  );
}
