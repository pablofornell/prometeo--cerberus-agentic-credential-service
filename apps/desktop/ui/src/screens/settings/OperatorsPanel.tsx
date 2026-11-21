import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import type { OperatorPublic_Serialize, OperatorRole, VaultStatusView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useOperators } from "../../ipc/queries";
import { Button, Chip, ConfirmDialog, Dialog, ErrorState, errorText, Field, IconButton, Input, Notice, Select, Skeleton, useToast } from "../../ui";
import { useStrength } from "../create/hooks";
import { Setting } from "./Setting";
import { messages } from "./messages";

const ROLES: readonly OperatorRole[] = ["owner", "operator", "viewer"];

/** The first letter of the name in a round tile. Decorative: the name is next to it. */
function Avatar({ name }: { name: string }) {
  return (
    <span className="op-avatar" aria-hidden="true">
      {name.trim().charAt(0).toUpperCase()}
    </span>
  );
}

export function OperatorsPanel({ status, canOwner }: { status: VaultStatusView; canOwner: boolean }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const operators = useOperators();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<OperatorPublic_Serialize | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<UiError | null>(null);

  const roleOptions = ROLES.map((r) => ({ value: r, label: t(`role.${r}`) }));
  const list = operators.data ?? [];
  const owners = list.filter((o) => o.role === "owner").length;
  const refresh = () => queryClient.invalidateQueries({ queryKey: qk.vault.operators() });

  const run = async (id: string, action: () => Promise<unknown>, done: string) => {
    setBusy(id);
    setError(null);
    try {
      await action();
      await refresh();
      toast.push({ tone: "success", title: done });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    } finally {
      setBusy(null);
    }
  };

  let body;
  if (operators.isPending) body = <Skeleton label={t("ops.loading")} rows={2} />;
  else if (operators.isError) body = <ErrorState action={t("ops.error")} error={operators.error} onRetry={() => void operators.refetch()} retrying={operators.isFetching} />;
  else if (list.length <= 1) {
    body = (
      <>
        <ul className="rows panel">{list.map((o) => row(o))}</ul>
        <p className="small muted">{t("ops.empty")}</p>
      </>
    );
  } else body = <ul className="rows panel">{list.map((o) => row(o))}</ul>;

  function row(o: OperatorPublic_Serialize) {
    const me = o.id === status.operator;
    const lastOwner = o.role === "owner" && owners <= 1;
    if (me) {
      return (
        <li key={o.id}>
          <Avatar name={o.label} />
          <span className="grow">
            {o.label} <span className="small muted">{t("ops.you")}</span>
          </span>
          <Chip>{t(`role.${o.role}`)}</Chip>
        </li>
      );
    }
    return (
      <li key={o.id}>
        <Avatar name={o.label} />
        <span className="grow">{o.label}</span>
        <Select
          aria-label={t("ops.role.aria", { name: o.label })}
          className="role-select"
          value={o.role}
          options={roleOptions}
          disabled={!canOwner || lastOwner || busy === o.id}
          onChange={(e) => void run(o.id, () => ipc.operatorSetRole(o.id, e.target.value as OperatorRole), t("ops.roleSet"))}
        />
        {canOwner && (
          <IconButton icon="trash" size="sm" label={t("ops.remove.aria", { name: o.label })} disabled={lastOwner || busy === o.id} onClick={() => setRemoving(o)} />
        )}
      </li>
    );
  }

  return (
    <Setting label={t("ops.label")} description={t("ops.desc")} wide ownerOnly={!canOwner}>
      {error && (
        <Notice tone="bad" title={t("save.error.title")} onDismiss={() => setError(null)} dismissLabel={t("save.dismiss")}>
          {errorText(error)} <span className="code">{t("save.error.line", { command: error.command, code: error.code })}</span>
        </Notice>
      )}
      {body}
      {canOwner && (
        <Button size="sm" icon="plus" className="self-start" onClick={() => setAdding(true)}>
          {t("ops.add")}
        </Button>
      )}
      <AddOperatorDialog open={adding} onOpenChange={setAdding} onAdded={() => void refresh()} />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t("ops.remove.title", { name: removing?.label ?? "" })}
        description={t("ops.remove.body")}
        confirmLabel={t("ops.remove.confirm")}
        tone="danger"
        loading={busy !== null}
        onConfirm={() => {
          const target = removing;
          setRemoving(null);
          if (target) void run(target.id, () => ipc.operatorRemove(target.id), t("ops.removed"));
        }}
      />
    </Setting>
  );
}

function AddOperatorDialog({ open, onOpenChange, onAdded }: { open: boolean; onOpenChange: (o: boolean) => void; onAdded: () => void }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const [label, setLabel] = useState("");
  const [role, setRole] = useState<OperatorRole>("operator");
  const [phrase, setPhrase] = useState("");
  const [again, setAgain] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const strength = useStrength(open ? phrase : "", [label]);

  const reset = () => {
    setLabel("");
    setRole("operator");
    setPhrase("");
    setAgain("");
    setTouched(false);
    setError(null);
    setBusy(false);
  };
  const close = (o: boolean) => {
    if (busy) return;
    if (!o) reset();
    onOpenChange(o);
  };

  const labelProblem = label.trim() === "" ? t("add.name.empty") : undefined;
  const phraseProblem = phrase.length < 12 ? t("phrase.short") : strength.status === "ready" && !strength.view.acceptable ? t("phrase.weak") : undefined;
  const againProblem = again !== phrase ? t("phrase.mismatch") : undefined;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (labelProblem || phraseProblem || againProblem) return;
    setBusy(true);
    setError(null);
    try {
      await ipc.operatorAdd(label.trim(), role, phrase);
      toast.push({ tone: "success", title: t("add.done") });
      onAdded();
      reset();
      onOpenChange(false);
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title={t("add.title")}
      description={t("add.desc")}
      footer={
        <>
          <Button onClick={() => close(false)} disabled={busy}>
            {t("cancel")}
          </Button>
          <Button variant="primary" type="submit" form="add-operator-form" loading={busy}>
            {t("add.submit")}
          </Button>
        </>
      }
    >
      <form id="add-operator-form" className="stack" noValidate onSubmit={(e) => void submit(e)}>
        {error && (
          <Notice tone="bad" title={t("add.fail")}>
            {errorText(error)} <span className="code block">{t("save.error.line", { command: error.command, code: error.code })}</span>
          </Notice>
        )}
        <Field label={t("add.label")} {...(touched && labelProblem ? { problem: labelProblem } : {})}>
          {(control) => <Input {...control} autoFocus autoComplete="off" value={label} onChange={(e) => setLabel(e.target.value)} />}
        </Field>
        <Field label={t("add.role")}>
          {(control) => <Select {...control} value={role} options={ROLES.map((r) => ({ value: r, label: t(`role.${r}`) }))} onChange={(e) => setRole(e.target.value as OperatorRole)} />}
        </Field>
        <Field label={t("add.phrase")} hint={t("phrase.new.hint")} {...(touched && phraseProblem ? { problem: phraseProblem } : {})}>
          {(control) => <Input {...control} mono type="password" autoComplete="new-password" value={phrase} onChange={(e) => setPhrase(e.target.value)} />}
        </Field>
        <Field label={t("add.phrase.again")} {...(touched && againProblem ? { problem: againProblem } : {})}>
          {(control) => <Input {...control} mono type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />}
        </Field>
      </form>
    </Dialog>
  );
}
