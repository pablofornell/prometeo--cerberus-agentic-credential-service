import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useLocation } from "wouter";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useVaultStatus } from "../../ipc/queries";
import { Button, GateMark, Notice, errorText, useToast } from "../../ui";
import { RestoreDialog } from "../settings/RestoreDialog";
import { messages } from "./messages";
import { UnlockForm } from "./UnlockForm";
import "./unlock.css";

function NoVault() {
  const t = useScreenT(messages);
  const [, navigate] = useLocation();
  const [restoring, setRestoring] = useState(false);
  return (
    <div className="unlock">
      <span className="mark"><GateMark size={120} /></span>
      <h1>{t("empty.title")}</h1>
      <p className="sub">{t("empty.body")}</p>
      <Button variant="primary" size="lg" icon="plus" className="center" onClick={() => navigate("~/create")}>
        {t("empty.create")}
      </Button>
      <Button size="lg" icon="upload" className="center" onClick={() => setRestoring(true)}>
        {t("empty.restore")}
      </Button>
      <p className="small muted center-text">{t("empty.note")}</p>
      <RestoreDialog open={restoring} onOpenChange={setRestoring} />
    </div>
  );
}

/**
 * A failed restore left the real vault as `<vault>.pre-restore-*` and no vault file (T27-G). Cerberus made no new
 * vault. It says where the old file is and offers one action: move the newest one back (the backend never overwrites).
 */
function Stranded({ paths }: { paths: string[] }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const [newest, ...older] = paths;

  const recover = async () => {
    setBusy(true);
    setError(null);
    try {
      await ipc.vaultRecoverStranded();
      toast.push({ tone: "success", title: t("stranded.done"), detail: t("stranded.done.detail") });
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
      setBusy(false);
    }
  };

  return (
    <div className="unlock">
      <span className="mark"><GateMark size={120} /></span>
      <h1>{t("stranded.title")}</h1>
      <p className="sub">{t("stranded.body")}</p>
      <div className="stack">
        <span className="label">{t("stranded.files")}</span>
        <code className="code block" data-testid="stranded-path">{newest}</code>
        {older.length > 0 && <p className="small muted">{t("stranded.more", { n: older.length })}</p>}
      </div>
      {error && (
        <Notice tone="bad" title={t("stranded.fail")}>
          {error.code === "conflict" ? t("stranded.conflict") : errorText(error)} <span className="code block">{t("stranded.fail.line", { command: error.command, code: error.code })}</span>
        </Notice>
      )}
      <Button variant="primary" size="lg" icon="upload" className="center" loading={busy} onClick={() => void recover()}>
        {t("stranded.recover")}
      </Button>
      <p className="small muted center-text">{t("stranded.note")}</p>
    </div>
  );
}

/** Screen 2: unlock. Calm and large. With no vault on the device it offers create and restore. */
export default function UnlockScreen() {
  const status = useVaultStatus();
  const stranded = status.data?.stranded_restore ?? [];
  return (
    <div className="unlock-screen" data-screen="unlock">
      {status.data?.state === "no_vault" ? stranded.length > 0 ? <Stranded paths={stranded} /> : <NoVault /> : <UnlockForm />}
    </div>
  );
}
