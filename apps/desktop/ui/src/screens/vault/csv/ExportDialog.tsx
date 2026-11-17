import { useState } from "react";
import { useScreenT } from "../../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../../ipc/client";
import { pickSavePath } from "../../../ipc/dialogs";
import { Button, Checkbox, Dialog, errorText, Field, Notice, Select, useToast } from "../../../ui";
import { useWorkspaces } from "../queries";
import { exportName } from "./fields";
import { messages } from "./messages";
import "./csv.css";

/**
 * Export to CSV. Owner only (the button is hidden for other roles and the backend checks again). The person must tick
 * that the file is not encrypted. The path comes from the native save dialog; the backend writes it with mode 0600.
 */
export function ExportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const workspaces = useWorkspaces();
  const [workspace, setWorkspace] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const [touched, setTouched] = useState(false);

  const reset = () => {
    setWorkspace("");
    setUnderstood(false);
    setBusy(false);
    setError(null);
    setTouched(false);
  };
  const close = (next: boolean) => {
    if (busy) return;
    if (!next) reset();
    onOpenChange(next);
  };

  const run = async () => {
    setTouched(true);
    if (!understood) return;
    setBusy(true);
    setError(null);
    try {
      const dest = await pickSavePath(exportName());
      if (!dest) return;
      const count = await ipc.csvExport(dest, workspace || null);
      toast.push({ tone: "success", title: tr("exp.done"), detail: tr("exp.done.detail", { count }) });
      reset();
      onOpenChange(false);
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title={tr("exp.title")}
      description={tr("exp.desc")}
      footer={
        <>
          <Button variant="ghost" onClick={() => close(false)} disabled={busy}>
            {tr("exp.cancel")}
          </Button>
          <Button variant="danger" icon="download" loading={busy} onClick={() => void run()}>
            {tr("exp.run")}
          </Button>
        </>
      }
    >
      <Notice tone="warn" title={tr("exp.warn.title")}>
        {tr("exp.warn.body")}
      </Notice>
      {error && (
        <Notice tone="bad" title={tr("exp.fail")} onDismiss={() => setError(null)} dismissLabel={tr("imp.close")}>
          {errorText(error)}
        </Notice>
      )}
      <Field label={tr("exp.scope")}>
        {(p) => (
          <Select
            {...p}
            value={workspace}
            onChange={(e) => setWorkspace(e.target.value)}
            options={[{ value: "", label: tr("exp.scope.all") }, ...(workspaces.data ?? []).map((w) => ({ value: w.id, label: w.name }))]}
          />
        )}
      </Field>
      <div className="field">
        <Checkbox label={tr("exp.confirm")} checked={understood} onChange={(e) => setUnderstood(e.target.checked)} aria-invalid={touched && !understood ? true : undefined} />
        {touched && !understood && <span className="problem">{tr("exp.confirm.needed")}</span>}
      </div>
    </Dialog>
  );
}
