import { useState } from "react";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { pickSavePath } from "../../ipc/dialogs";
import { Button, errorText, Notice, useToast } from "../../ui";
import { RestoreDialog } from "./RestoreDialog";
import { ExportButton, ImportButton } from "../vault/csv";
import { SectionHead, Setting, SettingGroup } from "./Setting";
import type { Can } from "./SecuritySection";
import { backupName } from "./files";
import { messages } from "./messages";

export function BackupSection({ can }: { can: Can }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const [restoring, setRestoring] = useState(false);

  const create = async () => {
    setError(null);
    try {
      const dest = await pickSavePath(backupName());
      if (!dest) return;
      setBusy(true);
      await ipc.backupCreate(dest);
      toast.push({ tone: "success", title: t("bk.saved"), detail: t("bk.saved.detail") });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section id="backup" aria-labelledby="bk-h" className="settings-section" data-section="backup">
      <SectionHead id="bk-h" icon="hardDrive" title={t("bk.title")} description={t("section.bk.desc")} />
      {error && (
        <Notice tone="bad" title={t("bk.fail")} onDismiss={() => setError(null)} dismissLabel={t("save.dismiss")}>
          {errorText(error)} <span className="code">{t("save.error.line", { command: error.command, code: error.code })}</span>
        </Notice>
      )}
      <Setting label={t("bk.create.label")} description={t("bk.create.desc")} operatorOnly={!can.operator}>
        <Button size="sm" variant="primary" icon="download" loading={busy} disabled={!can.operator} onClick={() => void create()}>
          {t("bk.create")}
        </Button>
      </Setting>
      <Setting label={t("csv.import.label")} description={t("csv.import.desc")} operatorOnly={!can.operator}>
        <ImportButton size="sm" disabled={!can.operator} />
      </Setting>
      <SettingGroup label={t("group.danger")} danger>
        <Setting label={t("bk.restore.label")} description={t("bk.restore.desc")} ownerOnly={!can.owner}>
          <Button size="sm" variant="danger-ghost" icon="upload" disabled={!can.owner} onClick={() => setRestoring(true)}>
            {t("bk.restore")}
          </Button>
        </Setting>
        <Setting label={t("csv.export.label")} description={t("csv.export.desc")} ownerOnly={!can.owner}>
          <ExportButton size="sm" disabled={!can.owner} />
        </Setting>
      </SettingGroup>
      <RestoreDialog open={restoring} onOpenChange={setRestoring} />
    </section>
  );
}
