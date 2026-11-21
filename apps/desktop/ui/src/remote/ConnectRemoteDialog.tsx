import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import type { RemoteProfileView } from "../bindings";
import { useScreenT } from "../i18n";
import { ipc, isIpcFailure, type UiError } from "../ipc/client";
import { openFile } from "../ipc/dialogs";
import { qk } from "../ipc/keys";
import { Button, Dialog, errorText, Notice, useToast } from "../ui";
import { messages } from "./messages";
import { ProfileFacts } from "./ProfileFacts";
import "./remote.css";

interface ConnectRemoteDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The local vault is unlocked (Settings): it is locked before the switch, which the backend asks for. */
  lockFirst?: boolean;
}

const failureOf = (failure: unknown, command: string): UiError =>
  isIpcFailure(failure) ? failure.error : { code: "ipc_unreachable", message: "", command, retryAfterSeconds: null, fields: [] };

/**
 * Connect to a remote server (ADR-0034 point 7.10): choose the bundle in the native dialog, check its pin and fingerprint
 * against `cerberusd status`, then switch. The switch restarts the app. Nothing secret reaches the page: the import
 * answers with the public facts only. A profile imported here and then cancelled is forgotten again.
 */
export function ConnectRemoteDialog({ open, onOpenChange, lockFirst = false }: ConnectRemoteDialogProps) {
  const t = useScreenT(messages);
  const queryClient = useQueryClient();
  const toast = useToast();
  const [profile, setProfile] = useState<RemoteProfileView | null>(null);
  const [busy, setBusy] = useState<"pick" | "connect" | null>(null);
  const [error, setError] = useState<UiError | null>(null);
  const chooseRef = useRef<HTMLButtonElement>(null);
  const connectRef = useRef<HTMLButtonElement>(null);

  const reset = () => {
    setProfile(null);
    setBusy(null);
    setError(null);
  };

  const close = () => {
    // The import is only staged: a cancel drops it, and a stored profile of the same enrolment stays as it was.
    if (profile) void ipc.remoteDiscardImport().catch(() => undefined);
    reset();
    onOpenChange(false);
    void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
  };

  const choose = async () => {
    setBusy("pick");
    setError(null);
    try {
      const path = await openFile({ title: t("connect.choose.title"), filters: [{ name: "Cerberus admin bundle", extensions: ["cerberus-admin", "json"] }] });
      if (path !== null) {
        // A new import replaces the staged one.
        const view = await ipc.remoteImportBundle(path);
        setProfile(view);
        queueMicrotask(() => connectRef.current?.focus());
      }
    } catch (failure) {
      setError(failureOf(failure, "remote_import_bundle"));
    } finally {
      setBusy(null);
    }
  };

  const connect = async () => {
    if (!profile) return;
    setBusy("connect");
    setError(null);
    try {
      // One call: the backend checks everything, then locks the local vault (lockFirst) and stores the import, so a
      // refused switch changes nothing and this dialog is still there to say why. The app restarts after it.
      await ipc.remoteActivate(profile.id, lockFirst);
      reset();
      onOpenChange(false);
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
      await queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
    } catch (failure) {
      const ui = failureOf(failure, "remote_activate");
      setError(ui);
      setBusy(null);
      // If the lock went through before a later step failed, this dialog is gone with the unlocked screens: the toast
      // outlives it.
      toast.push({ tone: "error", title: t("connect.failedActivate"), detail: errorText(ui) });
    }
  };

  const failure = error && (
    <Notice tone="bad" title={profile ? t("connect.failedActivate") : t("connect.failed")}>
      {errorText(error)} <span className="code block">{`${error.command}: ${error.code}`}</span>
    </Notice>
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => (next ? onOpenChange(true) : close())}
      title={t("connect.title")}
      description={t("connect.desc")}
      initialFocus={chooseRef}
      footer={
        profile ? (
          <>
            <Button onClick={close} disabled={busy !== null}>
              {t("connect.cancel")}
            </Button>
            <Button ref={connectRef} variant="primary" icon="plug" loading={busy === "connect"} onClick={() => void connect()}>
              {lockFirst ? t("connect.lockAndGo") : t("connect.go")}
            </Button>
          </>
        ) : (
          <Button onClick={close} disabled={busy !== null}>
            {t("connect.cancel")}
          </Button>
        )
      }
    >
      <div className="remote-connect">
        {profile ? (
          <>
            <Notice tone="warn" title={t("connect.check.title")}>
              {t("connect.check.body")}
            </Notice>
            <ProfileFacts label={profile.label} url={profile.url} operator={profile.operator_id} notAfter={profile.not_after} caPin={profile.ca_pin} caSha256={profile.ca_sha256} />
            <p className="note">
              {t("connect.delete")} {t("connect.restart")}
            </p>
            <Button ref={chooseRef} size="sm" variant="ghost" className="choose" disabled={busy !== null} onClick={() => void choose()}>
              {t("connect.back")}
            </Button>
          </>
        ) : (
          <>
            <p className="note">{t("connect.steps")}</p>
            <Button ref={chooseRef} variant="primary" icon="upload" className="choose" loading={busy === "pick"} onClick={() => void choose()}>
              {t("connect.choose")}
            </Button>
          </>
        )}
        {failure}
      </div>
    </Dialog>
  );
}
