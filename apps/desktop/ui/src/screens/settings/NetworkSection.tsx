import { useState, type FormEvent } from "react";
import type { NetworkView_Serialize } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { openFile, pickSavePath } from "../../ipc/dialogs";
import { Button, Chip, ConfirmDialog, Dialog, ErrorState, errorText, Field, Input, Notice, SegmentedControl, Skeleton, StatusDot, useToast } from "../../ui";
import { Setting } from "./Setting";
import type { Can } from "./SecuritySection";
import { settingsKeys, useNetwork } from "./queries";
import { messages } from "./messages";
import { useQueryClient } from "@tanstack/react-query";

const LOOPBACK = ["127.0.0.1", "::1"];
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6 = /^[0-9A-Fa-f:]+$/;

export const validAddress = (text: string): boolean => {
  const v4 = IPV4.exec(text);
  if (v4) return v4.slice(1).every((p) => Number(p) <= 255);
  return text.includes(":") && IPV6.test(text) && text.length <= 39;
};

export function NetworkSection({ can }: { can: Can }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const net = useNetwork();
  const queryClient = useQueryClient();
  const [binding, setBinding] = useState(false);
  const [custom, setCustom] = useState(false);
  const [local, setLocal] = useState(false);
  const [localBusy, setLocalBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);

  const dateFormat = new Intl.DateTimeFormat("en", { day: "numeric", month: "long", year: "numeric" });

  const copyPin = async (pin: string) => {
    try {
      await navigator.clipboard.writeText(pin);
      toast.push({ tone: "success", title: t("pin.copied"), detail: t("pin.copied.detail") });
    } catch {
      toast.push({ tone: "error", title: t("pin.copy.error") });
    }
  };

  const switchToLocalCa = async () => {
    setLocalBusy(true);
    setError(null);
    try {
      queryClient.setQueryData(settingsKeys.network(), await ipc.tlsUseLocalCa());
      toast.push({ tone: "success", title: t("cert.local.done") });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    } finally {
      setLocalBusy(false);
      setLocal(false);
    }
  };

  const exportCa = async () => {
    setError(null);
    try {
      const dest = await pickSavePath("cerberus-ca.pem");
      if (!dest) return;
      await ipc.tlsExportCa(dest);
      toast.push({ tone: "success", title: t("ca.saved") });
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    }
  };

  let body;
  if (net.isPending) body = <Skeleton label={t("bind.loading")} rows={3} />;
  else if (net.isError) body = <ErrorState action={t("bind.error")} error={net.error} onRetry={() => void net.refetch()} retrying={net.isFetching} />;
  else {
    const n = net.data;
    body = (
      <>
        {error && (
          <Notice tone="bad" title={t("ca.fail")} onDismiss={() => setError(null)} dismissLabel={t("save.dismiss")}>
            {errorText(error)} <span className="code">{t("save.error.line", { command: error.command, code: error.code })}</span>
          </Notice>
        )}
        {n.custom_cert && <Notice tone="warn" title={t("cert.warn.active")}>{t("cert.warn.active.body")}</Notice>}
        <Setting label={t("bind.label")} description={t("bind.desc")} ownerOnly={!can.owner}>
          {n.bind.map((a) => (
            <Chip key={a} className="mono">{a}</Chip>
          ))}
          <Chip className="mono">{t("bind.port", { port: n.port })}</Chip>
          <StatusDot tone={n.listening ? "ok" : "bad"}>{n.listening ? t("bind.listening") : `${t("bind.stopped")}${n.error ? `: ${n.error}` : ""}`}</StatusDot>
          {n.mtls_required && <Chip>{t("bind.mtls")}</Chip>}
          <Button size="sm" disabled={!can.owner} onClick={() => setBinding(true)}>
            {t("bind.change")}
          </Button>
        </Setting>
        <Setting label={t("pin.label")} description={<span className="fp">{n.pin}</span>}>
          <Button size="sm" icon="copy" onClick={() => void copyPin(n.pin)}>
            {t("pin.copy")}
          </Button>
        </Setting>
        <Setting
          label={n.custom_cert ? t("ca.label.custom") : t("ca.label")}
          description={
            <>
              {n.custom_cert ? t("ca.desc.custom") : t("ca.desc")} <span className="fp">{n.ca_fingerprint}</span>
            </>
          }
        >
          <Button size="sm" icon="download" onClick={() => void exportCa()}>
            {t("ca.export")}
          </Button>
        </Setting>
        <Setting label={t("cert.label")} description={n.leaf_not_after ? t(n.custom_cert ? "cert.valid.custom" : "cert.valid", { date: dateFormat.format(new Date(n.leaf_not_after)) }) : t("cert.unknown")} ownerOnly={!can.owner}>
          {n.custom_cert && <Chip>{t("cert.custom.chip")}</Chip>}
          <Button size="sm" variant="ghost" disabled={!can.owner} onClick={() => setCustom(true)}>
            {t("cert.custom")}
          </Button>
          {n.custom_cert && (
            <Button size="sm" variant="ghost" disabled={!can.owner} onClick={() => setLocal(true)}>
              {t("cert.local")}
            </Button>
          )}
        </Setting>
        <CustomCertDialog open={custom} onOpenChange={setCustom} />
        <ConfirmDialog
          open={local}
          onOpenChange={(o) => !localBusy && setLocal(o)}
          title={t("cert.local.title")}
          description={t("cert.local.body")}
          confirmLabel={t("cert.local.confirm")}
          tone="danger"
          loading={localBusy}
          onConfirm={() => void switchToLocalCa()}
        />
        <BindDialog open={binding} onOpenChange={setBinding} network={n} />
      </>
    );
  }

  return (
    <section id="network" aria-labelledby="net-h" className="settings-section" data-section="network">
      <h2 id="net-h" tabIndex={-1}>
        {t("net.title")}
      </h2>
      {body}
    </section>
  );
}

function BindDialog({ open, onOpenChange, network }: { open: boolean; onOpenChange: (o: boolean) => void; network: NetworkView_Serialize }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const isLocal = network.bind.every((a) => LOOPBACK.includes(a));
  const [mode, setMode] = useState<"local" | "lan">(isLocal ? "local" : "lan");
  const [addr, setAddr] = useState(isLocal ? "" : (network.bind.find((a) => !LOOPBACK.includes(a)) ?? ""));
  const [port, setPort] = useState(String(network.port));
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);

  const portNumber = Number(port);
  const portProblem = !/^\d+$/.test(port) || portNumber < 1024 || portNumber > 65_535 ? t("bind.port.problem") : undefined;
  const addrProblem = mode === "lan" && !validAddress(addr.trim()) ? t("bind.lan.problem") : undefined;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (portProblem || addrProblem) return;
    setBusy(true);
    setError(null);
    try {
      const addrs = mode === "local" ? LOOPBACK : [addr.trim()];
      const view = await ipc.networkSetBind(addrs, portNumber);
      queryClient.setQueryData(settingsKeys.network(), view);
      toast.push({ tone: "success", title: t("bind.done") });
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
      onOpenChange={(o) => !busy && onOpenChange(o)}
      title={t("bind.dlg.title")}
      description={t("bind.dlg.desc")}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)} disabled={busy}>
            {t("cancel")}
          </Button>
          <Button variant="primary" type="submit" form="bind-form" loading={busy}>
            {t("bind.submit")}
          </Button>
        </>
      }
    >
      <form id="bind-form" className="stack" noValidate onSubmit={(e) => void submit(e)}>
        {error && (
          <Notice tone="bad" title={t("save.error.title")}>
            {error.fields[0]?.problem ?? errorText(error)} <span className="code block">{t("save.error.line", { command: error.command, code: error.code })}</span>
          </Notice>
        )}
        <div className="field">
          <span className="label">{t("bind.mode")}</span>
          <SegmentedControl
            label={t("bind.mode")}
            size="lg"
            value={mode}
            onChange={setMode}
            options={[
              { value: "local", label: t("bind.mode.local") },
              { value: "lan", label: t("bind.mode.lan") },
            ]}
          />
        </div>
        {mode === "lan" && (
          <Field label={t("bind.lan.addr")} hint={t("bind.lan.hint")} {...(touched && addrProblem ? { problem: addrProblem } : {})}>
            {(control) => <Input {...control} mono autoComplete="off" spellCheck={false} value={addr} onChange={(e) => setAddr(e.target.value)} />}
          </Field>
        )}
        <Field label={t("bind.port.label")} {...(touched && portProblem ? { problem: portProblem } : {})}>
          {(control) => <Input {...control} mono inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />}
        </Field>
      </form>
    </Dialog>
  );
}

function PathField({ label, hint, value, onChange, problem }: { label: string; hint?: string; value: string; onChange: (v: string) => void; problem?: string | undefined }) {
  const t = useScreenT(messages);
  const choose = async () => {
    try {
      const picked = await openFile({ title: label });
      if (picked) onChange(picked);
    } catch {
      // No native dialog (a plain browser): the person types the path.
    }
  };
  return (
    <Field label={label} {...(hint ? { hint } : {})} {...(problem ? { problem } : {})}>
      {(control) => (
        <div className="input-row">
          <Input {...control} mono autoComplete="off" spellCheck={false} value={value} onChange={(e) => onChange(e.target.value)} />
          <Button onClick={() => void choose()}>{t("cert.choose")}</Button>
        </div>
      )}
    </Field>
  );
}

function CustomCertDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const t = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [chain, setChain] = useState("");
  const [key, setKey] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);

  const reset = () => {
    setChain("");
    setKey("");
    setTouched(false);
    setError(null);
    setBusy(false);
  };
  const close = (o: boolean) => {
    if (busy) return;
    if (!o) reset();
    onOpenChange(o);
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (chain.trim() === "" || key.trim() === "") return;
    setBusy(true);
    setError(null);
    try {
      queryClient.setQueryData(settingsKeys.network(), await ipc.tlsLoadCustom(chain.trim(), key.trim()));
      toast.push({ tone: "success", title: t("cert.done") });
      reset();
      onOpenChange(false);
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
      setBusy(false);
    }
  };
  const reason = error?.fields.find((f) => f.field === "certificate")?.problem;
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title={t("cert.dlg.title")}
      description={t("cert.dlg.desc")}
      footer={
        <>
          <Button onClick={() => close(false)} disabled={busy}>
            {t("cancel")}
          </Button>
          <Button variant="primary" type="submit" form="cert-form" loading={busy}>
            {t("cert.submit")}
          </Button>
        </>
      }
    >
      <form id="cert-form" className="stack" noValidate onSubmit={(e) => void submit(e)}>
        <Notice tone="warn" title={t("cert.warn")} />
        <Notice tone="warn" title={t("cert.pin.title")}>{t("cert.pin.body")}</Notice>
        {error && (
          <Notice tone="bad" title={t("cert.fail")}>
            <span className="code block">{t("save.error.line", { command: error.command, code: error.code })}</span>
          </Notice>
        )}
        <PathField label={t("cert.chain")} hint={t("cert.chain.hint")} value={chain} onChange={setChain} problem={reason ?? (touched && chain.trim() === "" ? t("cert.file.empty") : error ? errorText(error) : undefined)} />
        <PathField label={t("cert.key")} value={key} onChange={setKey} problem={touched && key.trim() === "" ? t("cert.file.empty") : undefined} />
      </form>
    </Dialog>
  );
}
