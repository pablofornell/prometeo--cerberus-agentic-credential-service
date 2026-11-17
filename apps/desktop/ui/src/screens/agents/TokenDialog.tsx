import { useEffect, useState } from "react";
import { ipc, isIpcFailure } from "../../ipc/client";
import { vaultStateStore } from "../../state/live";
import { Button, Checkbox, Dialog, errorText, useToast } from "../../ui";
import { useAgentsT } from "./format";

export interface TokenReveal {
  /** The token text. It lives only in the state of the screen that opened this dialog. */
  token: string;
  kind: "create" | "rotate";
  /** Seconds the old key keeps working (rotate). */
  overlapSeconds?: number;
}

interface TokenDialogProps {
  reveal: TokenReveal | null;
  /** Clears the token. The dialog calls it on Done and when the vault closes. */
  onDone: () => void;
}

const overlapText = (seconds: number): string => (seconds >= 86_400 ? `${Math.round(seconds / 86_400)} d` : `${Math.round(seconds / 3600)} h`);

/** The one-time token view. Copy goes through `clipboard_copy_once`; Done stays off until the person confirms. */
export function TokenDialog({ reveal, onDone }: TokenDialogProps) {
  const s = useAgentsT();
  const toast = useToast();
  const [stored, setStored] = useState(false);

  // The value must not outlive the vault session (ADR-0010).
  useEffect(
    () =>
      vaultStateStore.subscribe(() => {
        const state = vaultStateStore.get();
        if (state !== "unlocked" && state !== "unknown") onDone();
      }),
    [onDone],
  );

  const copy = async () => {
    try {
      await ipc.clipboardCopyOnce("agent_token");
      toast.push({ tone: "success", title: s("token.copied"), ringSeconds: 30 });
    } catch (error) {
      toast.push({ tone: "error", title: s("token.copyFailed"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    }
  };

  const done = () => {
    setStored(false);
    onDone();
  };

  return (
    <Dialog
      open={reveal !== null}
      onOpenChange={() => undefined}
      dismissible={false}
      title={s(reveal?.kind === "rotate" ? "token.title.rotate" : "token.title.create")}
      description={s("token.body")}
      footer={
        <Button variant="primary" disabled={!stored} onClick={done}>
          {s("token.done")}
        </Button>
      }
    >
      {reveal && (
        <div className="stack">
          <div className="token-box">
            <span className="token-label">{s("token.label")}</span>
            <code className="token" data-no-i18n>
              {reveal.token}
            </code>
          </div>
          {reveal.overlapSeconds ? <p className="small secondary">{s("token.overlap", { time: overlapText(reveal.overlapSeconds) })}</p> : null}
          <div className="row-inline">
            <Button icon="copy" onClick={() => void copy()}>
              {s("token.copy")}
            </Button>
          </div>
          <Checkbox label={s("token.stored")} checked={stored} onChange={(e) => setStored(e.target.checked)} />
        </div>
      )}
    </Dialog>
  );
}
