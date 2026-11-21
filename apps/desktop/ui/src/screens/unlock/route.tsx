import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useLocation } from "wouter";
import type { RemoteStatusView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useVaultStatus } from "../../ipc/queries";
import { ConnectRemoteDialog } from "../../remote/ConnectRemoteDialog";
import { messages as remoteMessages } from "../../remote/messages";
import { ProfileFacts } from "../../remote/ProfileFacts";
import { Button, Notice, errorText, useToast } from "../../ui";
import { RestoreDialog } from "../settings/RestoreDialog";
import { Brand } from "./Brand";
import { messages } from "./messages";
import { UnlockForm } from "./UnlockForm";
import "./unlock.css";

function NoVault() {
  const t = useScreenT(messages);
  const [, navigate] = useLocation();
  const [restoring, setRestoring] = useState(false);
  return (
    <div className="unlock">
      <Brand title={t("empty.title")}>
        <p className="sub">{t("empty.body")}</p>
      </Brand>
      <div className="actions">
        <Button variant="primary" size="lg" icon="plus" className="center" onClick={() => navigate("~/create")}>
          {t("empty.create")}
        </Button>
        <Button size="lg" icon="upload" className="center" onClick={() => setRestoring(true)}>
          {t("empty.restore")}
        </Button>
      </div>
      <p className="foot">{t("empty.note")}</p>
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
      <Brand title={t("stranded.title")}>
        <p className="sub">{t("stranded.body")}</p>
      </Brand>
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
      <p className="foot">{t("stranded.note")}</p>
    </div>
  );
}

/** The server cannot be used now: unreachable, another CA, another protocol, or this desktop is not enrolled any more. */
function RemoteProblem({ remote }: { remote: RemoteStatusView }) {
  const r = useScreenT(remoteMessages);
  const status = useVaultStatus();
  const queryClient = useQueryClient();
  const code = remote.problem ?? "remote_unreachable";
  const title =
    code === "remote_pin_mismatch"
      ? r("pin.title")
      : code === "remote_protocol_mismatch"
        ? r("protocol.title")
        : code === "admin_cert_required"
          ? r("revoked.title")
          : r("unreachable.title", { label: remote.label });
  const body = code === "admin_cert_required" ? r("revoked.body") : errorText({ code, message: "", command: "vault_status", retryAfterSeconds: null, fields: [] });
  return (
    <div className="unlock">
      <Brand mode="locked" title={title}>
        <p className="sub reason">{body}</p>
      </Brand>
      <ProfileFacts label={remote.label} url={remote.url} operator={remote.operator_id} notAfter={remote.not_after} />
      <div className="actions">
        <Button
          variant="primary"
          size="lg"
          icon="refresh"
          className="center"
          loading={status.isFetching}
          onClick={() => {
            void queryClient.invalidateQueries({ queryKey: qk.vault.status() });
            void queryClient.invalidateQueries({ queryKey: qk.vault.operators() });
          }}
        >
          {r("unreachable.retry")}
        </Button>
      </div>
      <p className="foot code">{`vault_status: ${code}`}</p>
    </div>
  );
}

/** Under the card: the way to the other backend. A quiet link, last in the tab order, so the card stays as it is. */
function OtherBackend({ remote }: { remote: RemoteStatusView | null }) {
  const r = useScreenT(remoteMessages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [connecting, setConnecting] = useState(false);
  const [switching, setSwitching] = useState(false);
  const switchToLocal = async () => {
    setSwitching(true);
    try {
      // The app restarts in local mode.
      await ipc.remoteActivate(null, false);
      await queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    } catch (failure) {
      toast.push({ tone: "error", title: r("local.use.failed"), detail: isIpcFailure(failure) ? errorText(failure.error) : undefined });
    } finally {
      setSwitching(false);
    }
  };
  return (
    <div className="unlock-alt">
      {remote ? (
        <Button size="sm" variant="ghost" icon="vault" loading={switching} onClick={() => void switchToLocal()}>
          {r("local.use")}
        </Button>
      ) : (
        <Button size="sm" variant="ghost" icon="server" onClick={() => setConnecting(true)}>
          {r("connect.open")}
        </Button>
      )}
      <ConnectRemoteDialog open={connecting} onOpenChange={setConnecting} />
    </div>
  );
}

/**
 * Screen 2: unlock. One quiet card on the grid. With no vault on the device it offers create and restore. Under the card
 * a quiet link connects to a remote server (ADR-0034), or, in remote mode, goes back to the local vault.
 */
export default function UnlockScreen() {
  const status = useVaultStatus();
  const stranded = status.data?.stranded_restore ?? [];
  const remote = status.data?.remote ?? null;
  let card;
  if (remote) card = remote.reachable && remote.problem === null ? <UnlockForm remote={remote} /> : <RemoteProblem remote={remote} />;
  else if (status.data?.state === "no_vault") card = stranded.length > 0 ? <Stranded paths={stranded} /> : <NoVault />;
  else card = <UnlockForm />;
  return (
    <>
      <div className="unlock-screen" data-screen="unlock">
        {card}
      </div>
      {stranded.length === 0 && <OtherBackend remote={remote} />}
    </>
  );
}
