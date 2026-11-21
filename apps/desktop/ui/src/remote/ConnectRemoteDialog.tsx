import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import type { RemoteProfileView } from "../bindings";
import { useScreenT } from "../i18n";
import { ipc, isIpcFailure, type UiError } from "../ipc/client";
import { openFile } from "../ipc/dialogs";
import { qk } from "../ipc/keys";
import { Button, Dialog, errorText, Notice } from "../ui";
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
  const [profile, setProfile] = useState<RemoteProfileView | null>(null);
  const [known, setKnown] = useState(false);
  const [busy, setBusy] = useState<"pick" | "connect" | null>(null);
  const [error, setError] = useState<UiError | null>(null);
  const chooseRef = useRef<HTMLButtonElement>(null);
  const connectRef = useRef<HTMLButtonElement>(null);

  const reset = () => {
    setProfile(null);
    setKnown(false);
    setBusy(null);
    setError(null);
  };

  const close = () => {
    // A bundle imported in this dialog and not used is not kept.
    if (profile && !known) void ipc.remoteForget(profile.id).catch(() => undefined);
    reset();
    onOpenChange(false);
    void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
  };

  const choose = async () => {
    setBusy("pick");
    setError(null);
    try {
      const before = await ipc.remoteStatus().catch(() => null);
      const path = await openFile({ title: t("connect.choose.title"), filters: [{ name: "Cerberus admin bundle", extensions: ["cerberus-admin", "json"] }] });
      if (path !== null) {
        if (profile && !known) await ipc.remoteForget(profile.id).catch(() => undefined);
        const view = await ipc.remoteImportBundle(path);
        setKnown(before?.profiles.some((p) => p.id === view.id) ?? false);
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
      if (lockFirst) await ipc.vaultLock();
      // The app restarts into remote mode now; the status follows.
      await ipc.remoteActivate(profile.id);
      reset();
      onOpenChange(false);
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
      await queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
    } catch (failure) {
      setError(failureOf(failure, "remote_activate"));
      setBusy(null);
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
