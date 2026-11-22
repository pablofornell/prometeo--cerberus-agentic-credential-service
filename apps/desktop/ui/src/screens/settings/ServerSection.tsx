import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { RemoteProfileView, VaultStatusView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useOperators, useRemoteOverview } from "../../ipc/queries";
import { ConnectRemoteDialog } from "../../remote/ConnectRemoteDialog";
import { ProfileFacts } from "../../remote/ProfileFacts";
import { openSetupDialog } from "../../shell/setupFlow";
import { Button, ConfirmDialog, errorText, Notice, Skeleton, StatusDot, useToast } from "../../ui";
import { SectionHead, Setting, SettingGroup } from "./Setting";
import { messages } from "./messages";

const formatDate = (iso: string): string => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/**
 * Remote server (ADR-0034 point 7.9). Local mode: connect this desktop to a server, and the imported bundles. Remote
 * mode: the server in use with its pin and fingerprint, Test connection, Disconnect (the server vault stays open),
 * Lock the server vault, and the way back to the local vault. Each switch restarts the app.
 */
export function ServerSection({ status }: { status: VaultStatusView }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const overview = useRemoteOverview();
  const operators = useOperators();
  const remote = status.remote ?? null;
  const [connecting, setConnecting] = useState(false);
  const [confirmLock, setConfirmLock] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<UiError | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null);

  const run = async (key: string, action: () => Promise<unknown>, done?: string) => {
    setBusy(key);
    setError(null);
    try {
      await action();
      if (done) toast.push({ tone: "success", title: done });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    } finally {
      setBusy(null);
      void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
      void queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    }
  };

  // The local vault is open here (Settings needs an unlocked vault). The backend locks it only after every check of the
  // switch passed, in the same call, so a refused switch leaves this screen up with its error. A failure is also a
  // toast, which outlives this screen if the lock went through before a later step failed (DEC-RM-26).
  const activate = async (id: string | null) => {
    const key = `use:${id ?? "local"}`;
    setBusy(key);
    setError(null);
    try {
      await ipc.remoteActivate(id, !remote);
    } catch (failure) {
      const ui = isIpcFailure(failure) ? failure.error : null;
      setError(ui);
      toast.push({ tone: "error", title: t("srv.fail"), detail: ui ? errorText(ui) : undefined });
    } finally {
      setBusy(null);
      void queryClient.invalidateQueries({ queryKey: qk.vault.remote() });
      void queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    }
  };

  const testConnection = async () => {
    setBusy("test");
    setTest(null);
    try {
      const fresh = await ipc.vaultStatus();
      queryClient.setQueryData(qk.vault.status(), fresh);
      const link = fresh.remote;
      if (link?.reachable && link.problem === null) setTest({ ok: true, text: t("srv.test.ok", { version: link.server_version ?? "?" }) });
      else setTest({ ok: false, text: t("srv.test.bad", { reason: errorText({ code: link?.problem ?? "remote_unreachable", message: "", command: "vault_status", retryAfterSeconds: null, fields: [] }) }) });
    } catch (failure) {
      setTest({ ok: false, text: t("srv.test.bad", { reason: isIpcFailure(failure) ? errorText(failure.error) : "" }) });
    } finally {
      setBusy(null);
    }
  };

  const profiles = overview.data?.profiles ?? [];
  const active = remote ? profiles.find((p) => p.id === remote.profile_id) : undefined;
  const others = profiles.filter((p) => p.id !== remote?.profile_id);

  const profileRow = (p: RemoteProfileView) => (
    <li key={p.id}>
      <span className="grow">
        {p.label} <span className="small muted mono">{p.url}</span> <span className="small muted">{t("srv.profile.expires", { date: formatDate(p.not_after) })}</span>
      </span>
      <Button size="sm" icon="plug" loading={busy === `use:${p.id}`} disabled={busy !== null} onClick={() => void activate(p.id)}>
        {remote ? t("srv.profile.use") : t("srv.profile.lockAndUse")}
      </Button>
      <Button size="sm" variant="ghost" aria-label={t("srv.profile.forget.aria", { label: p.label })} disabled={busy !== null} onClick={() => void run(`forget:${p.id}`, () => ipc.remoteForget(p.id), t("srv.forgotten"))}>
        {t("srv.profile.forget")}
      </Button>
    </li>
  );

  return (
    <section id="server" aria-labelledby="srv-h" className="settings-section" data-section="server">
      <SectionHead
        id="srv-h"
        icon="server"
        title={t("srv.title")}
        description={t("section.srv.desc")}
        aside={
          remote && (
            <>
              <StatusDot tone={remote.reachable ? "ok" : "bad"}>{remote.reachable ? t("srv.state.reachable") : t("srv.state.unreachable")}</StatusDot>
              {remote.server_state && (
                <StatusDot tone={remote.server_state === "unlocked" ? "ok" : "off"}>{remote.server_state === "unlocked" ? t("srv.state.server.unlocked") : t("srv.state.server.sealed")}</StatusDot>
              )}
            </>
          )
        }
      />
      {error && (
        <Notice tone="bad" title={t("srv.fail")} onDismiss={() => setError(null)} dismissLabel={t("save.dismiss")}>
          {errorText(error)} <span className="code">{t("save.error.line", { command: error.command, code: error.code })}</span>
        </Notice>
      )}
      {remote ? (
        <>
          <Setting
            wide
            label={t("srv.active.label", { label: remote.label })}
            description={t("srv.active.desc")}
          >
            <ProfileFacts
              label={remote.label}
              url={remote.url}
              operator={operators.data?.find((o) => o.id === remote.operator_id)?.label ?? remote.operator_id}
              notAfter={remote.not_after}
              {...(active ? { caPin: active.ca_pin, caSha256: active.ca_sha256 } : {})}
              serverVersion={remote.server_version}
            />
          </Setting>
          <Setting
            label={t("srv.test.label")}
            description={
              <>
                {t("srv.test.desc")}
                {test && (
                  <span className={test.ok ? "result" : "result bad"} role="status">
                    {test.text}
                  </span>
                )}
              </>
            }
          >
            <Button size="sm" icon="refresh" loading={busy === "test"} disabled={busy !== null && busy !== "test"} onClick={() => void testConnection()}>
              {t("srv.test")}
            </Button>
          </Setting>
          <Setting label={t("srv.disconnect.label")} description={t("srv.disconnect.desc")}>
            <Button size="sm" icon="unplug" loading={busy === "disconnect"} disabled={busy !== null} onClick={() => void run("disconnect", () => ipc.remoteDisconnect())}>
              {t("srv.disconnect")}
            </Button>
          </Setting>
          <Setting label={t("srv.local.use.label")} description={t("srv.local.use.desc")}>
            <Button size="sm" variant="ghost" icon="vault" loading={busy === "use:local"} disabled={busy !== null} onClick={() => void activate(null)}>
              {t("srv.local.use")}
            </Button>
          </Setting>
          {others.length > 0 && (
            <Setting wide label={t("srv.others.label")} description={t("srv.others.desc")}>
              <ul className="rows panel">{others.map(profileRow)}</ul>
            </Setting>
          )}
          <SettingGroup label={t("group.danger")} danger>
            <Setting label={t("srv.lock.label")} description={t("srv.lock.desc")}>
              <Button size="sm" variant="danger-ghost" icon="lock" disabled={busy !== null} onClick={() => setConfirmLock(true)}>
                {t("srv.lock")}
              </Button>
            </Setting>
          </SettingGroup>
          <ConfirmDialog
            open={confirmLock}
            onOpenChange={setConfirmLock}
            tone="danger"
            title={t("srv.lock.confirm.title", { label: remote.label })}
            description={t("srv.lock.confirm.body")}
            confirmLabel={t("srv.lock")}
            loading={busy === "lock"}
            onConfirm={() => {
              setConfirmLock(false);
              void run("lock", () => ipc.vaultLock(), t("srv.lock.done"));
            }}
          />
        </>
      ) : (
        <>
          <Setting label={t("srv.local.label")} description={t("srv.local.desc")}>
            <Button size="sm" icon="server" disabled={busy !== null} onClick={() => setConnecting(true)}>
              {t("srv.connect")}
            </Button>
          </Setting>
          <Setting label={t("srv.setup.label")} description={t("srv.setup.desc")}>
            <Button size="sm" icon="plus" disabled={busy !== null} onClick={() => openSetupDialog(true)}>
              {t("srv.setup")}
            </Button>
          </Setting>
          {overview.isPending ? (
            <Skeleton label={t("srv.loading")} rows={1} />
          ) : (
            others.length > 0 && (
              <Setting wide label={t("srv.profiles.label")} description={t("srv.profiles.desc")}>
                <ul className="rows panel">{others.map(profileRow)}</ul>
              </Setting>
            )
          )}
          <ConnectRemoteDialog open={connecting} onOpenChange={setConnecting} lockFirst />
        </>
      )}
    </section>
  );
}
