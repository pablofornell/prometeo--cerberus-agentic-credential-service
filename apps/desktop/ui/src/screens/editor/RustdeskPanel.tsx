import { useId, useState } from "react";
import { useScreenT } from "../../i18n";
import { Button, Field, Input } from "../../ui";
import { SecretInput } from "./fields";
import { messages } from "./messages";
import type { FormState } from "./model";
import { PasswordGenerator } from "./PasswordGenerator";

interface Props {
  state: FormState;
  patch: (patch: Partial<FormState>) => void;
  problems: Record<string, string>;
  /** An edited item keeps its password until the person replaces it. */
  editing: boolean;
}

/**
 * RustDesk kind: the connection (ID, servers, key) is item metadata and can change at any time; the permanent password
 * is the secret. Editing never reads the password: it stays until "Replace password".
 */
export function RustdeskPanel({ state, patch, problems, editing }: Props) {
  const tr = useScreenT(messages);
  const [genOpen, setGenOpen] = useState(false);
  const genId = useId();
  return (
    <fieldset className="ed-group">
      <legend>{tr("rd.legend")}</legend>
      <div className="form-grid">
        <Field label={tr("rd.id")} hint={tr("rd.id.hint")} problem={problems["custom.rustdesk_id"]}>
          {(p) => <Input {...p} mono inputMode="numeric" autoComplete="off" value={state.rdId} onChange={(e) => patch({ rdId: e.target.value })} />}
        </Field>
        <Field label={tr("rd.idServer")} hint={tr("rd.server.hint")} problem={problems["custom.id_server"]}>
          {(p) => <Input {...p} mono autoComplete="off" placeholder="rd.example.com" value={state.rdIdServer} onChange={(e) => patch({ rdIdServer: e.target.value })} />}
        </Field>
        <Field label={tr("rd.relayServer")} hint={tr("rd.server.hint")} problem={problems["custom.relay_server"]}>
          {(p) => <Input {...p} mono autoComplete="off" placeholder="rd.example.com:21117" value={state.rdRelayServer} onChange={(e) => patch({ rdRelayServer: e.target.value })} />}
        </Field>
        <Field label={tr("rd.key")} hint={tr("rd.key.hint")} problem={problems["custom.server_key"]}>
          {(p) => <Input {...p} mono autoComplete="off" spellCheck={false} value={state.rdKey} onChange={(e) => patch({ rdKey: e.target.value })} />}
        </Field>
        {state.keepSecret ? (
          <div className="field full">
            <span className="label">{tr("rd.password")}</span>
            <p className="secondary">{tr("rd.password.kept")}</p>
            <div>
              <Button onClick={() => patch({ keepSecret: false, rdPassword: "" })}>{tr("rd.password.replace")}</Button>
            </div>
          </div>
        ) : (
          <Field className="full" label={tr("rd.password")} hint={tr(editing ? "rd.password.replacing" : "rd.password.hint")} problem={problems["payload.password"]}>
            {(p) => (
              <>
                <SecretInput
                  label={tr("rd.password")}
                  control={p}
                  value={state.rdPassword}
                  onChange={(rdPassword) => patch({ rdPassword })}
                  extra={
                    <Button aria-expanded={genOpen} aria-controls={genId} onClick={() => setGenOpen((o) => !o)}>
                      {tr("gen.open")}
                    </Button>
                  }
                />
                {genOpen && <PasswordGenerator id={genId} onGenerated={(rdPassword) => patch({ rdPassword })} />}
                {editing && (
                  <div>
                    <Button size="sm" variant="ghost" onClick={() => patch({ keepSecret: true, rdPassword: "" })}>
                      {tr("rd.password.keep")}
                    </Button>
                  </div>
                )}
              </>
            )}
          </Field>
        )}
      </div>
    </fieldset>
  );
}
