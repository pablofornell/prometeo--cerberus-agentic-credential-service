import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import type { Value } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc } from "../../ipc/client";
import { Button, Field, Input } from "../../ui";
import { rustdeskKeys, useRustdeskStatus } from "../vault/rustdesk";
import { Setting } from "./Setting";
import type { Can } from "./SecuritySection";
import { messages } from "./messages";

interface Props {
  values: Record<string, Value>;
  can: Can;
  pending: string | null;
  onSet: (key: string, value: Value) => void;
}

/** The RustDesk client that Connect on a RustDesk item starts (DEC-RD-3). A desktop setting of this computer, not of the vault. */
export function RemoteSection({ values, can, pending, onSet }: Props) {
  const t = useScreenT(messages);
  const queryClient = useQueryClient();
  const status = useRustdeskStatus();
  const saved = typeof values.rustdesk_path === "string" ? values.rustdesk_path : "";

  // A new program changes what Connect would start: look again.
  useEffect(() => {
    void queryClient.invalidateQueries({ queryKey: rustdeskKeys.status() });
  }, [saved, queryClient]);

  let found: string;
  if (status.isPending) found = t("rd.checking");
  else if (status.isError) found = t("rd.unknown");
  else if (status.data.client) found = t("rd.found", { program: status.data.client.program, how: t(`rd.how.${status.data.client.kind}`) });
  else found = status.data.custom_path ? t("rd.customMissing") : t("rd.notFound");

  return (
    <section id="remote" aria-labelledby="rd-h" className="settings-section" data-section="remote">
      <h2 id="rd-h" tabIndex={-1}>
        {t("rd.title")}
      </h2>
      <Setting
        wide
        label={t("rd.client.label")}
        description={
          <>
            {t("rd.client.desc")} <span aria-live="polite">{found}</span>
          </>
        }
        operatorOnly={!can.operator}
      >
        <PathForm key={saved} saved={saved} disabled={!can.operator || pending === "rustdesk_path"} onSave={(value) => onSet("rustdesk_path", value)} />
      </Setting>
    </section>
  );
}

function PathForm({ saved, disabled, onSave }: { saved: string; disabled: boolean; onSave: (value: string | null) => void }) {
  const t = useScreenT(messages);
  const [text, setText] = useState(saved);
  const choose = async () => {
    const picked = await ipc.filePickOpen(t("rd.choose.title"), []).catch(() => null);
    if (picked) setText(picked);
  };
  const trimmed = text.trim();
  return (
    <div className="stack">
      <Field label={t("rd.path.label")} hint={t("rd.path.hint")}>
        {(p) => <Input {...p} mono autoComplete="off" spellCheck={false} placeholder={t("rd.path.auto")} disabled={disabled} value={text} onChange={(e) => setText(e.target.value)} />}
      </Field>
      <div className="row-inline">
        <Button size="sm" disabled={disabled} onClick={() => void choose()}>
          {t("rd.choose")}
        </Button>
        <Button size="sm" variant="primary" disabled={disabled || trimmed === saved} onClick={() => onSave(trimmed === "" ? null : trimmed)}>
          {t("rd.save")}
        </Button>
        <Button size="sm" variant="ghost" disabled={disabled || saved === ""} onClick={() => onSave(null)}>
          {t("rd.auto")}
        </Button>
      </div>
    </div>
  );
}
