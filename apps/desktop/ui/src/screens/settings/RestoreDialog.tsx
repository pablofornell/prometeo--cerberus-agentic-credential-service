import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import type { RestoreUnlockInput } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { openFile } from "../../ipc/dialogs";
import { qk } from "../../ipc/keys";
import { useOperators } from "../../ipc/queries";
import { Button, Dialog, errorText, Field, Input, Notice, SegmentedControl, Select, Textarea, useToast } from "../../ui";
import { messages } from "./messages";

type Method = "phrase" | "recovery";

/**
 * Restore a backup over the current vault (or onto an empty device). The credential is typed here and sent once;
 * it is cleared when the dialog closes. After a restore the vault is sealed, so the guard moves to the unlock screen.
 */
export function RestoreDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const operators = useOperators();
  const list = operators.data ?? [];
  const [path, setPath] = useState("");
  const [method, setMethod] = useState<Method>("recovery");
  const [operatorId, setOperatorId] = useState("");
  const [secret, setSecret] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);

  const canPhrase = list.length > 0;
  const effective: Method = canPhrase ? method : "recovery";
  const chosenOperator = operatorId || list[0]?.id || "";

  const reset = () => {
    setPath("");
    setSecret("");
    setTouched(false);
    setError(null);
    setBusy(false);
  };
  const close = (o: boolean) => {
    if (busy) return;
    if (!o) reset();
    onOpenChange(o);
  };

  const choose = async () => {
    try {
      const picked = await openFile();
      if (picked) setPath(picked);
    } catch {
      // The dialog is not available (a plain browser). The person can type the path.
    }
  };

  const pathProblem = path.trim() === "" ? t("rs.empty.file") : undefined;
  const secretProblem = error?.code === "bad_credentials" ? t("rs.wrong") : secret.trim() === "" ? t("rs.empty.secret") : undefined;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (pathProblem || secret.trim() === "") return;
    setBusy(true);
    setError(null);
    const unlock: RestoreUnlockInput =
      effective === "phrase"
        ? { kind: "phrase", operator_id: chosenOperator, phrase: secret }
        : { kind: "recovery", recovery_key: secret.trim() };
    try {
      await ipc.backupRestore(path.trim(), unlock);
      toast.push({ tone: "success", title: t("rs.done"), detail: t("rs.done.detail") });
      reset();
      onOpenChange(false);
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
      setSecret("");
      setBusy(false);
    }
  };

  const generic = error && error.code !== "bad_credentials" ? error : null;
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title={t("rs.title")}
      description={t("rs.desc")}
      footer={
        <>
          <Button onClick={() => close(false)} disabled={busy}>
            {t("cancel")}
          </Button>
          <Button variant="danger" type="submit" form="restore-form" icon="upload" loading={busy}>
            {t("rs.submit")}
          </Button>
        </>
      }
    >
      <form id="restore-form" className="stack" noValidate onSubmit={(e) => void submit(e)}>
        <Notice tone="warn" title={t("rs.warn")} />
        {generic && (
          <Notice tone="bad" title={t("rs.fail")}>
            {errorText(generic)} <span className="code block">{t("save.error.line", { command: generic.command, code: generic.code })}</span>
          </Notice>
        )}
        <Field label={t("rs.file")} hint={t("rs.file.hint")} {...(touched && pathProblem ? { problem: pathProblem } : {})}>
          {(control) => (
            <div className="input-row">
              <Input {...control} mono autoComplete="off" spellCheck={false} value={path} onChange={(e) => setPath(e.target.value)} />
              <Button onClick={() => void choose()}>{t("rs.choose")}</Button>
            </div>
          )}
        </Field>
        {canPhrase && (
          <div className="field">
            <span className="label">{t("rs.method")}</span>
            <SegmentedControl
              label={t("rs.method")}
              value={method}
              onChange={setMethod}
              options={[
                { value: "recovery", label: t("rs.method.recovery") },
                { value: "phrase", label: t("rs.method.phrase") },
              ]}
            />
          </div>
        )}
        {effective === "phrase" ? (
          <>
            <Field label={t("rs.operator")}>
              {(control) => <Select {...control} value={chosenOperator} options={list.map((o) => ({ value: o.id, label: o.label }))} onChange={(e) => setOperatorId(e.target.value)} />}
            </Field>
            <Field label={t("rs.phrase")} {...((touched || error?.code === "bad_credentials") && secretProblem ? { problem: secretProblem } : {})}>
              {(control) => <Input {...control} mono type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />}
            </Field>
          </>
        ) : (
          <Field label={t("rs.recovery")} {...((touched || error?.code === "bad_credentials") && secretProblem ? { problem: secretProblem } : {})}>
            {(control) => <Textarea {...control} mono rows={3} autoComplete="off" spellCheck={false} value={secret} onChange={(e) => setSecret(e.target.value)} />}
          </Field>
        )}
      </form>
    </Dialog>
  );
}
