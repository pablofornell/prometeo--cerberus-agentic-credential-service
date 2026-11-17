import { useState } from "react";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { Button, CLIPBOARD_CLEAR_SECONDS, ConfirmDialog, Dialog, Checkbox, errorText, Notice, useToast } from "../../ui";
import { RecoveryKeyGrid } from "../create/RecoveryKeyGrid";
import { messages } from "./messages";

/** Rotate the recovery key: confirm, then one-time reveal. The key lives in this component and is dropped on close. */
export function RecoveryRotate({ disabled }: { disabled: boolean }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [key, setKey] = useState<string | null>(null);
  const [stored, setStored] = useState(false);
  const [error, setError] = useState<UiError | null>(null);

  const rotate = async () => {
    setBusy(true);
    setError(null);
    try {
      const fresh = await ipc.recoveryRotate();
      setKey(fresh);
      setStored(false);
      setConfirm(false);
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
      setConfirm(false);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    try {
      await ipc.clipboardCopyOnce("recovery_key");
      toast.push({ tone: "success", title: t("rot.copied"), detail: t("rot.copied.detail"), ringSeconds: CLIPBOARD_CLEAR_SECONDS });
    } catch {
      toast.push({ tone: "error", title: t("rot.copy.error") });
    }
  };

  const close = () => {
    setKey(null);
    setStored(false);
  };

  return (
    <>
      <Button size="sm" disabled={disabled} onClick={() => setConfirm(true)}>
        {t("recovery.rotate")}
      </Button>
      {error && (
        <div className="setting-error">
          <Notice tone="bad" title={t("rot.fail")} onDismiss={() => setError(null)} dismissLabel={t("save.dismiss")}>
            {errorText(error)} <span className="code">{t("save.error.line", { command: error.command, code: error.code })}</span>
          </Notice>
        </div>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={(o) => !busy && setConfirm(o)}
        title={t("rot.title")}
        description={t("rot.body")}
        confirmLabel={t("rot.confirm")}
        tone="danger"
        loading={busy}
        onConfirm={() => void rotate()}
      />
      <Dialog
        open={key !== null}
        onOpenChange={() => undefined}
        dismissible={false}
        title={t("rot.reveal.title")}
        description={t("rot.reveal.body")}
        footer={
          <Button variant="primary" disabled={!stored} onClick={close}>
            {t("rot.done")}
          </Button>
        }
      >
        <div className="stack">
          {key !== null && <RecoveryKeyGrid recoveryKey={key} />}
          <div className="row-inline">
            <Button size="sm" icon="download" onClick={() => window.print()}>
              {t("rot.print")}
            </Button>
            <Button size="sm" icon="copy" onClick={() => void copy()}>
              {t("rot.copy")}
            </Button>
          </div>
          <Checkbox label={t("rot.stored")} checked={stored} onChange={(e) => setStored(e.target.checked)} />
        </div>
      </Dialog>
    </>
  );
}
