import { useId, useState, type FormEvent } from "react";
import type { AgentKeyInputView_Deserialize, AgentKeyView_Serialize, AgentView_Serialize, Scope } from "../../bindings";
import { useQueryClient } from "@tanstack/react-query";
import { t } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useCan } from "../../state/session";
import { Button, Checkbox, Dialog, errorText, Field, Input, Notice, Select } from "../../ui";
import { useAgentsT } from "./format";
import { messages } from "./messages";
import type { TokenReveal } from "./TokenDialog";

export const SCOPES: readonly Scope[] = ["status:read", "catalog:read", "secrets:read", "secrets:write", "sessions:write", "requests", "ssh:use"];
const DEFAULT_SCOPES: readonly Scope[] = ["status:read", "catalog:read", "secrets:read", "sessions:write", "requests"];

type Life = "30" | "90" | "365" | "none";

function toKeyInput(scopes: readonly Scope[], life: Life, ips: string): AgentKeyInputView_Deserialize {
  return {
    scopes: SCOPES.filter((sc) => scopes.includes(sc)),
    lifetime_days: life === "none" ? null : Number(life),
    ip_allowlist: ips.split(",").map((x) => x.trim()).filter(Boolean),
  };
}

function KeyFields({ scopes, setScopes, life, setLife, ips, setIps }: {
  scopes: readonly Scope[];
  setScopes: (next: Scope[]) => void;
  life: Life;
  setLife: (life: Life) => void;
  ips: string;
  setIps: (ips: string) => void;
}) {
  const s = useAgentsT();
  const isOwner = useCan("owner");
  const toggle = (scope: Scope, on: boolean) => setScopes(on ? [...scopes, scope] : scopes.filter((x) => x !== scope));
  return (
    <>
      <Field label={s("create.life")}>
        {(p) => (
          <Select
            {...p}
            value={life}
            onChange={(e) => setLife(e.target.value as Life)}
            options={[
              { value: "30", label: s("create.life.30") },
              { value: "90", label: s("create.life.90") },
              { value: "365", label: s("create.life.365") },
              ...(isOwner ? [{ value: "none", label: s("create.life.none") }] : []),
            ]}
          />
        )}
      </Field>
      <Field label={s("create.ip")} hint={s("create.ip.hint")}>
        {(p) => <Input {...p} mono value={ips} onChange={(e) => setIps(e.target.value)} placeholder="127.0.0.1/32, ::1/128" autoComplete="off" spellCheck={false} />}
      </Field>
      <fieldset className="field full scopes-field">
        <legend className="label">{s("create.scopes")}</legend>
        <div className="form-grid">
          {SCOPES.map((scope) => (
            <Checkbox
              key={scope}
              label={scope}
              hint={s(`scope.${scope}`)}
              checked={scopes.includes(scope)}
              onChange={(e) => toggle(scope, e.target.checked)}
            />
          ))}
        </div>
      </fieldset>
    </>
  );
}

interface CreateProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (agentId: string, reveal: TokenReveal) => void;
}

/** New agent: name, description and the first key. The token reply goes straight to `onCreated`, never into a cache. */
export function CreateAgentDialog({ open, onOpenChange, onCreated }: CreateProps) {
  const s = useAgentsT();
  const queryClient = useQueryClient();
  const formId = useId();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [life, setLife] = useState<Life>("90");
  const [scopes, setScopes] = useState<Scope[]>([...DEFAULT_SCOPES]);
  const [ips, setIps] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setName("");
    setDescription("");
    setLife("90");
    setScopes([...DEFAULT_SCOPES]);
    setIps("");
    setProblem(null);
    setFailure(null);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (name.trim() === "") {
      setProblem(s("create.name.required"));
      return;
    }
    setProblem(null);
    setFailure(null);
    setBusy(true);
    try {
      const result = await ipc.agentCreate({ name: name.trim(), description: description.trim() }, toKeyInput(scopes, life, ips));
      reset();
      onOpenChange(false);
      await queryClient.invalidateQueries({ queryKey: qk.agents() });
      onCreated(result.agent.id, { token: result.token, kind: "create" });
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy(false);
    }
  };

  const ui = isIpcFailure(failure) ? failure.error : null;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      wide
      title={s("create.title")}
      description={s("create.body")}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t("dialog.cancel")}</Button>
          <Button variant="primary" type="submit" form={formId} loading={busy}>
            {s("create.submit")}
          </Button>
        </>
      }
    >
      <form id={formId} className="form-grid" onSubmit={(e) => void submit(e)} noValidate>
        {failure !== null && (
          <div className="full">
            <Notice tone="bad" title={s("create.failed")}>
              {ui ? errorText(ui) : null}
              {ui?.fields.map((f) => (
                <span key={f.field} className="block small">
                  {f.field}: {f.problem}
                </span>
              ))}
            </Notice>
          </div>
        )}
        <Field label={s("create.name")} problem={problem ?? undefined}>
          {(p) => <Input {...p} value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={80} autoComplete="off" required />}
        </Field>
        <Field label={s("create.description")}>
          {(p) => <Input {...p} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={300} autoComplete="off" />}
        </Field>
        <KeyFields scopes={scopes} setScopes={setScopes} life={life} setLife={setLife} ips={ips} setIps={setIps} />
      </form>
    </Dialog>
  );
}

interface AddKeyProps {
  agent: AgentView_Serialize | null;
  onClose: () => void;
  onCreated: (reveal: TokenReveal) => void;
}

/** Adds a second key to an agent. */
export function AddKeyDialog({ agent, onClose, onCreated }: AddKeyProps) {
  const s = useAgentsT();
  const formId = useId();
  const [life, setLife] = useState<Life>("90");
  const [scopes, setScopes] = useState<Scope[]>([...DEFAULT_SCOPES]);
  const [ips, setIps] = useState("");
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!agent) return;
    setBusy(true);
    setFailure(null);
    try {
      const result = await ipc.agentKeyCreate(agent.id, toKeyInput(scopes, life, ips));
      await queryClient.invalidateQueries({ queryKey: qk.agents() });
      onClose();
      onCreated({ token: result.token, kind: "create" });
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy(false);
    }
  };

  const ui = isIpcFailure(failure) ? failure.error : null;
  return (
    <Dialog
      open={agent !== null}
      onOpenChange={(open) => !open && onClose()}
      wide
      title={s("addkey.title", { name: agent?.name ?? "" })}
      description={s("addkey.body")}
      footer={
        <>
          <Button onClick={onClose}>{t("dialog.cancel")}</Button>
          <Button variant="primary" type="submit" form={formId} loading={busy}>
            {s("addkey.submit")}
          </Button>
        </>
      }
    >
      <form id={formId} className="form-grid" onSubmit={(e) => void submit(e)}>
        {ui && (
          <div className="full">
            <Notice tone="bad" title={s("addkey.failed")}>
              {errorText(ui)}
            </Notice>
          </div>
        )}
        <KeyFields scopes={scopes} setScopes={setScopes} life={life} setLife={setLife} ips={ips} setIps={setIps} />
      </form>
    </Dialog>
  );
}

const OVERLAPS = [
  { value: "0", key: "rotate.overlap.0" },
  { value: "3600", key: "rotate.overlap.1h" },
  { value: "86400", key: "rotate.overlap.24h" },
  { value: "604800", key: "rotate.overlap.7d" },
] as const satisfies readonly { value: string; key: keyof typeof messages }[];

interface RotateProps {
  keyView: AgentKeyView_Serialize | null;
  onClose: () => void;
  onRotated: (reveal: TokenReveal) => void;
}

/** Rotates one key with an overlap time. */
export function RotateKeyDialog({ keyView, onClose, onRotated }: RotateProps) {
  const s = useAgentsT();
  const [overlap, setOverlap] = useState("86400");
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!keyView) return;
    setBusy(true);
    setFailure(null);
    try {
      const seconds = Number(overlap);
      const result = await ipc.agentKeyRotate(keyView.id, seconds);
      onClose();
      onRotated({ token: result.token, kind: "rotate", overlapSeconds: seconds });
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy(false);
    }
  };

  const ui = isIpcFailure(failure) ? failure.error : null;
  return (
    <Dialog
      open={keyView !== null}
      onOpenChange={(open) => !open && onClose()}
      title={s("rotate.title", { key: keyView ? `cvt_…${keyView.hint}` : "" })}
      description={s("rotate.body")}
      footer={
        <>
          <Button onClick={onClose}>{t("dialog.cancel")}</Button>
          <Button variant="primary" icon="refresh" loading={busy} onClick={() => void submit()}>
            {s("rotate.submit")}
          </Button>
        </>
      }
    >
      <div className="stack">
        {ui && (
          <Notice tone="bad" title={s("rotate.failed")}>
            {errorText(ui)}
          </Notice>
        )}
        <Field label={s("rotate.overlap")}>
          {(p) => <Select {...p} value={overlap} onChange={(e) => setOverlap(e.target.value)} options={OVERLAPS.map((o) => ({ value: o.value, label: s(o.key) }))} />}
        </Field>
      </div>
    </Dialog>
  );
}
