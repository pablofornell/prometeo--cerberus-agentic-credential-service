import { useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { t } from "../i18n";
import { ipc, isIpcFailure } from "../ipc/client";
import { pickSavePath } from "../ipc/dialogs";
import { qk } from "../ipc/keys";
import { useRemote } from "../state/backendMode";
import { usePrefs } from "../state/prefs";
import { errorText, useToast } from "../ui";
import type { CommandContext } from "./commands";
import { closeOverlay, openOverlay } from "./uiStore";

/** Everything a shell action needs, in one hook: lock, panic, audit check, exports, theme. */
export function useShellActions(): CommandContext {
  const [, navigate] = useLocation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const prefs = usePrefs();
  const remote = useRemote();

  const fail = (error: unknown) =>
    toast.push({
      tone: "error",
      title: t("palette.fail"),
      detail: isIpcFailure(error) ? errorText(error.error) : undefined,
    });

  // In remote mode "lock" ends this desktop's session; the server vault stays open for its agents (DEC-RM-8). Locking
  // the server vault itself is a separate action in Settings.
  const lock = () => {
    (remote ? ipc.remoteDisconnect() : ipc.vaultLock())
      .then(() => {
        if (remote) toast.push({ tone: "success", title: t("remote.disconnected") });
        return queryClient.invalidateQueries({ queryKey: qk.vault.status() });
      })
      .catch(fail);
  };

  const saveTo = async (name: string, run: (dest: string) => Promise<unknown>, done: string) => {
    try {
      const dest = await pickSavePath(name);
      if (dest === null) return;
      await run(dest);
      toast.push({ tone: "success", title: done });
    } catch (error) {
      fail(error);
    }
  };

  return {
    navigate,
    lock,
    panic: () => openOverlay("panic"),
    verifyAudit: () => {
      closeOverlay();
      ipc
        .auditVerify()
        .then((report) => {
          toast.push({ tone: report.ok ? "success" : "error", title: t(report.ok ? "palette.verify.ok" : "palette.verify.bad") });
          if (!report.ok) navigate("/audit");
        })
        .catch(fail);
    },
    exportCa: () => void saveTo("cerberus-ca.pem", (dest) => ipc.tlsExportCa(dest), t("palette.done.exportCa")),
    createBackup: () => void saveTo("cerberus-backup.cerb", (dest) => ipc.backupCreate(dest), t("palette.done.backup")),
    cycleTheme: prefs.cycleTheme,
    showShortcuts: () => openOverlay("shortcuts"),
    themeLabel: t(`palette.theme.${prefs.theme}`),
    remote: remote !== null,
  };
}
