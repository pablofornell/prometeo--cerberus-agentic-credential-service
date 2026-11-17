import { useState, type FormEvent } from "react";
import type { KdfTuningView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { Button, Checkbox, Dialog, errorText, Field, Input, Notice, useToast } from "../../ui";
import { useStrength } from "../create/hooks";
import { costSummary } from "../create/Steps";
import { messages } from "./messages";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The cost measured with "Test this device", if any. */
  tuning: KdfTuningView | null;
  defaultCost: boolean;
}

const MIN_LENGTH = 12;

/** Change the phrase of the signed-in operator. All three phrases live in this component and are cleared on close. */
export function PhraseDialog({ open, onOpenChange, tuning, defaultCost }: Props) {
  const t = useScreenT(messages);
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [costChoice, setCostChoice] = useState<boolean | null>(null);
  const useCost = costChoice ?? (defaultCost && tuning !== null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const [touched, setTouched] = useState(false);
  const strength = useStrength(open ? next : "", []);

  const reset = () => {
    setCurrent("");
    setNext("");
    setAgain("");
    setError(null);
    setTouched(false);
    setBusy(false);
    setCostChoice(null);
  };
  const close = (o: boolean) => {
    if (busy) return;
    if (!o) reset();
    onOpenChange(o);
  };

  const strongEnough = strength.status === "ready" && strength.view.acceptable;
  const newProblem = next.length < MIN_LENGTH ? t("phrase.short") : !strongEnough && strength.status === "ready" ? t("phrase.weak") : undefined;
  const againProblem = again !== next ? t("phrase.mismatch") : undefined;
  const currentProblem = error?.code === "bad_credentials" || current === "" ? t("phrase.wrong") : undefined;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (current === "" || newProblem || againProblem) return;
    setBusy(true);
    setError(null);
    try {
      await ipc.phraseChange(current, next, useCost && tuning ? tuning.params : null);
      toast.push({ tone: "success", title: t("phrase.done"), detail: t("phrase.done.detail") });
      reset();
      onOpenChange(false);
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
      setCurrent("");
      setBusy(false);
    }
  };

  const generic = error && error.code !== "bad_credentials" ? error : null;
  const cost = tuning ? costSummary(tuning.params) : null;
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title={t("phrase.dlg.title")}
      description={t("phrase.dlg.desc", { name: t("phrase.dlg.you") })}
      footer={
        <>
          <Button onClick={() => close(false)} disabled={busy}>
            {t("cancel")}
          </Button>
          <Button variant="primary" type="submit" form="phrase-form" loading={busy}>
            {t("phrase.submit")}
          </Button>
        </>
      }
    >
      <form id="phrase-form" className="stack" noValidate onSubmit={(e) => void submit(e)}>
        {generic && (
          <Notice tone="bad" title={t("phrase.fail")}>
            {generic.code === "unavailable" ? t("unavailable.kdf") : errorText(generic)}
            <span className="code block">{t("save.error.line", { command: generic.command, code: generic.code })}</span>
          </Notice>
        )}
        <Field label={t("phrase.current")} {...((touched || error?.code === "bad_credentials") && currentProblem ? { problem: currentProblem } : {})}>
          {(control) => <Input {...control} mono type="password" autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} />}
        </Field>
        <Field label={t("phrase.new")} hint={t("phrase.new.hint")} {...(touched && newProblem ? { problem: newProblem } : {})}>
          {(control) => <Input {...control} mono type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />}
        </Field>
        <Field label={t("phrase.again")} {...(touched && againProblem ? { problem: againProblem } : {})}>
          {(control) => <Input {...control} mono type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />}
        </Field>
        {cost && tuning && (
          <Checkbox label={t("phrase.cost", { memory: cost.memory, passes: cost.passes, lanes: cost.lanes })} checked={useCost} onChange={(e) => setCostChoice(e.target.checked)} />
        )}
      </form>
    </Dialog>
  );
}
