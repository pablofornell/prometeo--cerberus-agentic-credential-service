import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { ItemSummaryView_Serialize as Item } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { Button, CLIPBOARD_CLEAR_SECONDS, errorText, IconButton, Notice, useToast } from "../../ui";
import { messages } from "./messages";
import { invalidateItems } from "./queries";
import { carriesServer, rustdeskConnection, rustdeskLink, rustdeskShareText, useRustdeskStatus } from "./rustdesk";

interface Props {
  item: Item;
  /** The password is copied on Connect only when the role may reveal it. */
  canReveal: boolean;
}

/**
 * The connection of a RustDesk item: what to share (ID, servers, key, a `rustdesk://` link and one text with all of it)
 * and a Connect button that opens the local RustDesk client. None of it holds the password: Connect copies it to the
 * clipboard through the backend, which clears it after 30 s.
 */
export function RustdeskCard({ item, canReveal }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const status = useRustdeskStatus();
  const [busy, setBusy] = useState(false);
  const c = rustdeskConnection(item.custom);
  const link = rustdeskLink(c);
  const share = rustdeskShareText(c, {
    id: tr("rd.id"),
    idServer: tr("rd.idServer"),
    relayServer: tr("rd.relayServer"),
    serverKey: tr("rd.serverKey"),
    link: tr("rd.link"),
  });
  const missing = status.data !== undefined && status.data.client === null;

  /** The link and the text are not secret, so they go through the plain clipboard API. */
  const copyText = async (text: string, done: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.push({ tone: "success", title: done });
    } catch {
      toast.push({ tone: "error", title: tr("rd.copyFail") });
    }
  };

  const connect = async () => {
    setBusy(true);
    try {
      const result = await ipc.rustdeskConnect(item.id, canReveal);
      const opening = tr("rd.opening", { id: c.id });
      if (result.password === "copied") {
        toast.push({ tone: "success", title: tr("rd.passwordCopied"), detail: opening, ringSeconds: CLIPBOARD_CLEAR_SECONDS });
        invalidateItems(queryClient);
      } else if (result.password === "not_copied") {
        toast.push({ tone: "error", title: tr("rd.passwordNotCopied"), detail: opening });
      } else {
        toast.push({ tone: "info", title: opening, detail: result.password === "not_stored" ? tr("rd.noPassword") : undefined });
      }
    } catch (error) {
      toast.push({ tone: "error", title: tr("rd.connectFail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
      void status.refetch();
    } finally {
      setBusy(false);
    }
  };

  const row = (label: string, value: string | null, fallback: string) => (
    <>
      <dt>{label}</dt>
      <dd className={value ? "mono" : "muted"}>{value ?? fallback}</dd>
    </>
  );

  return (
    <section className="sec" aria-labelledby="vb-d-rd">
      <h3 id="vb-d-rd">{tr("rd.title")}</h3>
      <dl className="kv small">
        {row(tr("rd.id"), c.id, "")}
        {row(tr("rd.idServer"), c.idServer, tr("rd.publicServer"))}
        {row(tr("rd.relayServer"), c.relayServer, tr("rd.publicServer"))}
        {row(tr("rd.serverKey"), c.serverKey, tr("rd.noKey"))}
      </dl>
      <div className="vb-secret-row">
        <span className="field-k">{tr("rd.link")}</span>
        <span className="row-inline">
          <span className="mono small vb-rd-link">{link}</span>
          <IconButton icon="copy" size="sm" label={tr("rd.copyLink")} onClick={() => void copyText(link, tr("rd.linkCopied"))} />
        </span>
      </div>
      <div className="vb-secret-row">
        <span className="field-k">{tr("rd.share")}</span>
        <pre className="vb-rd-share">{share}</pre>
        <p className="small muted">{tr("rd.shareHint")}</p>
      </div>
      {c.idServer !== null && !carriesServer(c) && <Notice tone="warn" title={tr("rd.ipv6.title")}>{tr("rd.ipv6.body")}</Notice>}
      {c.relayServer !== null && <p className="small muted">{tr("rd.relayNote")}</p>}
      {carriesServer(c) && c.serverKey?.includes("+") && <p className="small muted">{tr("rd.plusKeyNote")}</p>}
      {missing && (
        <Notice tone="warn" title={tr("rd.missing.title")}>
          {status.data?.custom_path ? tr("rd.missing.custom", { path: status.data.custom_path }) : tr("rd.missing.body")}
        </Notice>
      )}
      <div className="row-inline">
        <Button variant="primary" icon="monitor" loading={busy} disabled={missing} onClick={() => void connect()}>
          {tr("rd.connect")}
        </Button>
        <Button icon="copy" onClick={() => void copyText(share, tr("rd.shareCopied"))}>
          {tr("rd.copyAll")}
        </Button>
      </div>
      <p className="small muted">{canReveal ? tr("rd.connectHint") : tr("rd.connectHintViewer")}</p>
    </section>
  );
}
