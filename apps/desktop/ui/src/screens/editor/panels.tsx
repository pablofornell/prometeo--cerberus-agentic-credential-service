import { useId, useState, type ReactNode } from "react";
import { useScreenT } from "../../i18n";
import type { ItemKind } from "../../bindings";
import { Button, Field, Input, SegmentedControl, Select, Textarea } from "../../ui";
import { PairsEditor, SecretInput } from "./fields";
import { messages } from "./messages";
import type { FormState } from "./model";
import { PasswordGenerator } from "./PasswordGenerator";
import { TotpPreview } from "./TotpPreview";

/** Kinds whose whole secret panel is replaced by `KeptSecretPanel` while an edited item keeps its secret. SSH and
 * RustDesk have their own panels: their metadata stays editable then. */
export type SecretPanelKind = Exclude<ItemKind, "ssh_key" | "rustdesk">;

export interface PanelProps {
  state: FormState;
  patch: (patch: Partial<FormState>) => void;
  /** Problems by field path (`payload.password`). */
  problems: Record<string, string>;
}

/** The text of every problem under a path prefix, for editors that have many rows. */
const under = (problems: Record<string, string>, prefix: string): string[] =>
  Object.entries(problems)
    .filter(([key]) => key === prefix || key.startsWith(`${prefix}.`))
    .map(([, value]) => value);

function Group({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <fieldset className="ed-group">
      <legend>{legend}</legend>
      <div className="form-grid">{children}</div>
    </fieldset>
  );
}

const LEGEND: Record<SecretPanelKind, keyof typeof messages> = {
  web_login: "web.legend",
  api_key: "api.legend",
  session_token: "session.legend",
  browser_session: "session.legend",
  database: "db.legend",
  cloud: "cloud.legend",
  certificate: "cert.legend",
  env_bundle: "env.legend",
  note: "note.legend",
};

/** An edited item keeps its secret. The form never reads it, so this stands in for the secret fields until "Replace". */
export function KeptSecretPanel({ kind, onReplace }: { kind: SecretPanelKind; onReplace: () => void }) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr(LEGEND[kind])}>
      <div className="field full">
        <p className="secondary">{tr("keep.body")}</p>
        <div>
          <Button onClick={onReplace}>{tr("keep.replace")}</Button>
        </div>
      </div>
    </Group>
  );
}

export function WebLoginPanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  const [genOpen, setGenOpen] = useState(false);
  const genId = useId();
  return (
    <Group legend={tr("web.legend")}>
      <Field label={tr("web.username")} problem={problems["payload.username"]}>
        {(p) => <Input {...p} mono autoComplete="off" value={state.webUsername} onChange={(e) => patch({ webUsername: e.target.value })} />}
      </Field>
      <Field label={tr("web.url")} problem={problems["payload.url"]}>
        {(p) => <Input {...p} mono value={state.webUrl} onChange={(e) => patch({ webUrl: e.target.value })} />}
      </Field>
      <Field className="full" label={tr("web.password")} problem={problems["payload.password"]}>
        {(p) => (
          <>
            <SecretInput
              label={tr("web.password")}
              control={p}
              value={state.webPassword}
              onChange={(webPassword) => patch({ webPassword })}
              extra={
                <Button aria-expanded={genOpen} aria-controls={genId} onClick={() => setGenOpen((o) => !o)}>
                  {tr("gen.open")}
                </Button>
              }
            />
            {genOpen && <PasswordGenerator id={genId} onGenerated={(webPassword) => patch({ webPassword })} />}
          </>
        )}
      </Field>
      <Field className="full" label={tr("web.totp")} hint={tr("web.totp.hint")} problem={problems["payload.totp"]}>
        {(p) => (
          <>
            <SecretInput label={tr("web.totp")} control={p} value={state.totpSecret} onChange={(totpSecret) => patch({ totpSecret })} />
            <details className="ed-advanced">
              <summary>{tr("web.totp.advanced")}</summary>
              <div className="form-grid">
                <Field label={tr("web.totp.algorithm")}>
                  {(q) => (
                    <Select
                      {...q}
                      value={state.totpAlgorithm}
                      onChange={(e) => patch({ totpAlgorithm: e.target.value as FormState["totpAlgorithm"] })}
                      options={[
                        { value: "SHA1", label: "SHA1" },
                        { value: "SHA256", label: "SHA256" },
                        { value: "SHA512", label: "SHA512" },
                      ]}
                    />
                  )}
                </Field>
                <Field label={tr("web.totp.digits")}>
                  {(q) => (
                    <Select
                      {...q}
                      value={state.totpDigits}
                      onChange={(e) => patch({ totpDigits: e.target.value })}
                      options={[
                        { value: "6", label: "6" },
                        { value: "8", label: "8" },
                      ]}
                    />
                  )}
                </Field>
                <Field label={tr("web.totp.period")}>
                  {(q) => <Input {...q} mono inputMode="numeric" value={state.totpPeriod} onChange={(e) => patch({ totpPeriod: e.target.value })} />}
                </Field>
              </div>
            </details>
            <TotpPreview secret={state.totpSecret} algorithm={state.totpAlgorithm} digits={Number(state.totpDigits)} period={Number(state.totpPeriod) || 30} />
          </>
        )}
      </Field>
    </Group>
  );
}

export function ApiKeyPanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("api.legend")}>
      <Field className="full" label={tr("api.key")} problem={problems["payload.key"]}>
        {(p) => <SecretInput label={tr("api.key")} control={p} value={state.apiKey} onChange={(apiKey) => patch({ apiKey })} />}
      </Field>
      <Field label={tr("api.keyId")} problem={problems["payload.key_id"]}>
        {(p) => <Input {...p} mono value={state.apiKeyId} onChange={(e) => patch({ apiKeyId: e.target.value })} />}
      </Field>
      <Field label={tr("api.header")} problem={problems["payload.header_name"]}>
        {(p) => <Input {...p} mono placeholder="Authorization" value={state.apiHeader} onChange={(e) => patch({ apiHeader: e.target.value })} />}
      </Field>
      <Field className="full" label={tr("api.baseUrl")} problem={problems["payload.base_url"]}>
        {(p) => <Input {...p} mono value={state.apiBaseUrl} onChange={(e) => patch({ apiBaseUrl: e.target.value })} />}
      </Field>
    </Group>
  );
}

export function SessionTokenPanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("session.legend")}>
      <Field className="full" label={tr("session.token")} problem={problems["payload.token"]}>
        {(p) => <SecretInput label={tr("session.token")} multiline rows={3} control={p} value={state.token} onChange={(token) => patch({ token })} />}
      </Field>
      <Field label={tr("session.tokenType")} problem={problems["payload.token_type"]}>
        {(p) => <Input {...p} mono placeholder="Bearer" value={state.tokenType} onChange={(e) => patch({ tokenType: e.target.value })} />}
      </Field>
      <Field label={tr("session.header")} problem={problems["payload.header_name"]}>
        {(p) => <Input {...p} mono value={state.tokenHeader} onChange={(e) => patch({ tokenHeader: e.target.value })} />}
      </Field>
    </Group>
  );
}

export function BrowserSessionPanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("session.legend")}>
      <Field className="full" label={tr("session.storage")} hint={tr("session.storage.hint")} problem={problems["payload.storage_state"]}>
        {(p) => <SecretInput label={tr("session.storage")} multiline rows={5} control={p} value={state.storageState} onChange={(storageState) => patch({ storageState })} />}
      </Field>
      <Field className="full" label={tr("session.origin")} problem={problems["payload.origin"]}>
        {(p) => <Input {...p} mono value={state.origin} onChange={(e) => patch({ origin: e.target.value })} />}
      </Field>
    </Group>
  );
}

export function DatabasePanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("db.legend")}>
      <div className="field full">
        <SegmentedControl
          label={tr("db.mode")}
          value={state.dbMode}
          onChange={(dbMode) => patch({ dbMode })}
          options={[
            { value: "url", label: tr("db.mode.url") },
            { value: "fields", label: tr("db.mode.fields") },
          ]}
        />
      </div>
      {state.dbMode === "url" ? (
        <Field className="full" label={tr("db.url")} hint={tr("db.url.hint")} problem={problems["payload.url"]}>
          {(p) => <SecretInput label={tr("db.url")} control={p} value={state.dbUrl} onChange={(dbUrl) => patch({ dbUrl })} />}
        </Field>
      ) : (
        <>
          <Field label={tr("db.engine")} problem={problems["payload.engine"]}>
            {(p) => <Input {...p} mono placeholder="postgres" value={state.dbEngine} onChange={(e) => patch({ dbEngine: e.target.value })} />}
          </Field>
          <Field label={tr("db.host")} problem={problems["payload.host"]}>
            {(p) => <Input {...p} mono value={state.dbHost} onChange={(e) => patch({ dbHost: e.target.value })} />}
          </Field>
          <Field label={tr("db.port")} problem={problems["payload.port"]}>
            {(p) => <Input {...p} mono inputMode="numeric" value={state.dbPort} onChange={(e) => patch({ dbPort: e.target.value })} />}
          </Field>
          <Field label={tr("db.name")} problem={problems["payload.database"]}>
            {(p) => <Input {...p} mono value={state.dbName} onChange={(e) => patch({ dbName: e.target.value })} />}
          </Field>
          <Field label={tr("db.user")} problem={problems["payload.username"]}>
            {(p) => <SecretInput label={tr("db.user")} control={p} value={state.dbUser} onChange={(dbUser) => patch({ dbUser })} />}
          </Field>
          <Field label={tr("db.password")} problem={problems["payload.password"]}>
            {(p) => <SecretInput label={tr("db.password")} control={p} value={state.dbPassword} onChange={(dbPassword) => patch({ dbPassword })} />}
          </Field>
        </>
      )}
      <PairsEditor legend={tr("db.params")} pairs={state.dbParams} onChange={(dbParams) => patch({ dbParams })} secret={false} problems={under(problems, "payload.params")} />
    </Group>
  );
}

export function CloudPanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("cloud.legend")}>
      <Field label={tr("cloud.provider")} problem={problems["payload.provider"]}>
        {(p) => <Input {...p} mono placeholder="aws" value={state.cloudProvider} onChange={(e) => patch({ cloudProvider: e.target.value })} />}
      </Field>
      <Field label={tr("cloud.region")} problem={problems["payload.region"]}>
        {(p) => <Input {...p} mono value={state.cloudRegion} onChange={(e) => patch({ cloudRegion: e.target.value })} />}
      </Field>
      <Field label={tr("cloud.keyId")} problem={problems["payload.access_key_id"]}>
        {(p) => <SecretInput label={tr("cloud.keyId")} control={p} value={state.cloudKeyId} onChange={(cloudKeyId) => patch({ cloudKeyId })} />}
      </Field>
      <Field label={tr("cloud.secret")} problem={problems["payload.secret_access_key"]}>
        {(p) => <SecretInput label={tr("cloud.secret")} control={p} value={state.cloudSecret} onChange={(cloudSecret) => patch({ cloudSecret })} />}
      </Field>
      <Field className="full" label={tr("cloud.token")} problem={problems["payload.session_token"]}>
        {(p) => <SecretInput label={tr("cloud.token")} control={p} value={state.cloudToken} onChange={(cloudToken) => patch({ cloudToken })} />}
      </Field>
      <PairsEditor legend={tr("cloud.extra")} pairs={state.cloudExtra} onChange={(cloudExtra) => patch({ cloudExtra })} secret problems={under(problems, "payload.extra")} />
    </Group>
  );
}

export function CertificatePanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("cert.legend")}>
      <Field className="full" label={tr("cert.pem")} problem={problems["payload.cert_pem"]}>
        {(p) => <Textarea {...p} mono rows={5} spellCheck={false} value={state.certPem} onChange={(e) => patch({ certPem: e.target.value })} />}
      </Field>
      <Field className="full" label={tr("cert.key")} problem={problems["payload.key_pem"]}>
        {(p) => <SecretInput label={tr("cert.key")} multiline rows={5} control={p} value={state.certKey} onChange={(certKey) => patch({ certKey })} />}
      </Field>
      <Field className="full" label={tr("cert.chain")} problem={problems["payload.chain_pem"]}>
        {(p) => <Textarea {...p} mono rows={4} spellCheck={false} value={state.certChain} onChange={(e) => patch({ certChain: e.target.value })} />}
      </Field>
    </Group>
  );
}

export function EnvBundlePanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("env.legend")}>
      <PairsEditor legend={tr("env.legend")} pairs={state.envVars} onChange={(envVars) => patch({ envVars })} secret upperNames problems={under(problems, "payload.vars")} />
    </Group>
  );
}

export function NotePanel({ state, patch, problems }: PanelProps) {
  const tr = useScreenT(messages);
  return (
    <Group legend={tr("note.legend")}>
      <Field className="full" label={tr("note.text")} problem={problems["payload.text"]}>
        {(p) => <SecretInput label={tr("note.text")} multiline rows={6} control={p} value={state.noteText} onChange={(noteText) => patch({ noteText })} />}
      </Field>
    </Group>
  );
}
