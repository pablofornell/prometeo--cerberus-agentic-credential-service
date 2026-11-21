import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent, type ReactElement } from "react";
import { useLocation } from "wouter";
import type { WorkspaceView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { useSettings } from "../../ipc/queries";
import { Button, cx, EnvBadge, errorText, Field, Icon, Input, KindIcon, Notice, Panel, Select, Textarea, useToast } from "../../ui";
import { BUILTIN_CATEGORIES, ENVIRONMENTS, formatDateTime, isSessionKind, KIND_ORDER, kindLabel } from "../vault/kinds";
import { invalidateItems, useAllItems } from "../vault/queries";
import { handoffSelection } from "../vault/selection";
import { WorkspaceDialog } from "../vault/WorkspaceDialog";
import { RoleChips } from "./fields";
import { messages } from "./messages";
import { type FormState, isInline, localProblems, normalizeField, toInput, withKind } from "./model";
import { ApiKeyPanel, BrowserSessionPanel, CertificatePanel, CloudPanel, DatabasePanel, EnvBundlePanel, KeptSecretPanel, NotePanel, SessionTokenPanel, WebLoginPanel, type PanelProps, type SecretPanelKind } from "./panels";
import { RustdeskPanel } from "./RustdeskPanel";
import { SshPanel } from "./SshPanel";

interface Props {
  initial: FormState;
  /** The item being edited, or `null` for a new item. */
  itemId: string | null;
  workspaces: readonly WorkspaceView[];
}

const NEW_WORKSPACE = "__new__";

const LOCAL_TEXT: Record<string, keyof typeof messages> = {
  title: "f.title.problem",
  workspace: "f.workspace.problem",
  key: "ssh.keyProblem",
  rustdeskId: "rd.idProblem",
  date: "f.expires.date.problem",
};

const SECONDS_LABEL: Record<number, keyof typeof messages> = {
  900: "ttl.15m",
  3600: "ttl.1h",
  28800: "ttl.8h",
  86400: "ttl.24h",
  604800: "ttl.7d",
  2592000: "ttl.30d",
};

const PANELS: Record<SecretPanelKind, (props: PanelProps) => ReactElement> = {
  web_login: WebLoginPanel,
  api_key: ApiKeyPanel,
  session_token: SessionTokenPanel,
  browser_session: BrowserSessionPanel,
  database: DatabasePanel,
  cloud: CloudPanel,
  certificate: CertificatePanel,
  env_bundle: EnvBundlePanel,
  note: NotePanel,
};

/** One form for every kind. The kind picker changes the secret panel. Backend field problems map onto the fields. */
export function ItemForm({ initial, itemId, workspaces }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [, navigate] = useLocation();
  const settings = useSettings();
  const items = useAllItems();
  const [state, setState] = useState<FormState>(initial);
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [other, setOther] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [wsOpen, setWsOpen] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const kindId = useId();
  const envId = useId();
  const categoriesId = useId();
  const editing = itemId !== null;

  const patch = (next: Partial<FormState>) => setState((prev) => ({ ...prev, ...next }));

  // After a failed save, focus goes to the first field with a problem.
  useEffect(() => {
    if (attempt === 0) return;
    form.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
  }, [attempt]);

  const maxTtl = Number(settings.data?.values.session_ttl_max_seconds ?? 86_400);
  const session = isSessionKind(state.kind);
  const expiryOptions = useMemo(() => {
    const out: { value: string; label: string }[] = [];
    if (state.currentExpiry) out.push({ value: "keep", label: `${tr("f.expires.keep")} (${formatDateTime(state.currentExpiry)})` });
    if (session) {
      const seconds = [900, 3600, 28_800, 86_400, 604_800].filter((s) => s <= maxTtl);
      if (!seconds.includes(maxTtl) && SECONDS_LABEL[maxTtl]) seconds.push(maxTtl);
      for (const s of seconds) {
        const label = tr(SECONDS_LABEL[s] ?? "ttl.1h");
        out.push({ value: String(s), label: s === maxTtl ? tr("ttl.max", { label }) : label });
      }
    } else {
      out.push({ value: "never", label: tr("f.expires.never") });
      for (const s of [3600, 86_400, 604_800, 2_592_000]) out.push({ value: String(s), label: tr(SECONDS_LABEL[s] ?? "ttl.1h") });
      out.push({ value: "date", label: tr("f.expires.date") });
    }
    return out;
  }, [state.currentExpiry, session, maxTtl, tr]);

  const categories = useMemo(() => {
    const names = new Set<string>(BUILTIN_CATEGORIES);
    for (const i of items.data ?? []) names.add(i.category);
    return [...names];
  }, [items.data]);

  const workspace = workspaces.find((w) => w.id === state.workspaceId);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const local = localProblems(state);
    if (Object.keys(local).length > 0) {
      setProblems(Object.fromEntries(Object.entries(local).map(([key, code]) => [key, tr(LOCAL_TEXT[code] ?? "f.title.problem")])));
      setOther([]);
      setAttempt((n) => n + 1);
      return;
    }
    setProblems({});
    setOther([]);
    setBusy(true);
    try {
      const input = toInput(state, Date.now());
      const saved = editing ? await ipc.itemUpdate(itemId, input) : await ipc.itemCreate(input);
      invalidateItems(queryClient);
      toast.push({ tone: "success", title: tr(editing ? "saved.updated" : "saved.created") });
      handoffSelection(saved.summary.id);
      navigate("~/vault");
    } catch (error) {
      const ui = isIpcFailure(error) ? error.error : null;
      if (ui && ui.fields.length > 0) {
        const next: Record<string, string> = {};
        const rest: string[] = [];
        for (const f of ui.fields) {
          const key = normalizeField(f.field);
          if (isInline(key) || isInline(f.field)) next[key] ??= f.problem;
          else rest.push(tr("banner.other", { field: f.field, problem: f.problem }));
        }
        setProblems(next);
        setOther(rest);
        setAttempt((n) => n + 1);
      } else {
        toast.push({ tone: "error", title: tr("save.fail"), detail: ui ? errorText(ui) : undefined });
      }
    } finally {
      setBusy(false);
    }
  };

  const count = Object.keys(problems).length + other.length;
  const panelProps: PanelProps = { state, patch, problems };
  const secretPanel = (() => {
    if (state.kind === "ssh_key") return <SshPanel state={state} patch={patch} problems={problems} />;
    if (state.kind === "rustdesk") return <RustdeskPanel state={state} patch={patch} problems={problems} editing={editing} />;
    if (state.keepSecret) return <KeptSecretPanel kind={state.kind} onReplace={() => patch({ keepSecret: false })} />;
    const Panel_ = PANELS[state.kind];
    return (
      <>
        {editing && (
          <Notice
            tone="warn"
            title={tr("keep.replacing")}
            actions={
              <Button size="sm" onClick={() => patch({ keepSecret: true })}>
                {tr("keep.cancel")}
              </Button>
            }
          >
            {tr("keep.replacingBody")}
          </Notice>
        )}
        <Panel_ {...panelProps} />
      </>
    );
  })();
  const ask = [`  app: "${workspace?.slug ?? "…"}",`, `  environment: "${state.environment}"`, ...(state.roleLabel.trim() ? [`  role: "${state.roleLabel.trim()}"`] : [])];
  if (state.roleLabel.trim()) ask[1] += ",";

  return (
    <form
      ref={form}
      className="ed-layout"
      noValidate
      aria-labelledby="page-title"
      onSubmit={(e) => void submit(e)}
      onKeyDown={(e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
          e.preventDefault();
          form.current?.requestSubmit();
        }
      }}
    >
      <div className="ed-formcol">
        {count > 0 && (
          <Notice tone="bad" title={tr(count === 1 ? "banner.one" : "banner.many", { count })}>
            {tr("banner.nothingSaved")}
            {other.length > 0 && (
              <ul className="ed-other">
                {other.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            )}
          </Notice>
        )}

        <fieldset className="ed-group">
          <legend>{tr("group.kind")}</legend>
          <div className="ed-kinds" role="radiogroup" aria-label={tr("kind.aria")}>
            {KIND_ORDER.map((kind) => (
              <label key={kind}>
                <input type="radio" name={kindId} value={kind} checked={state.kind === kind} disabled={editing && state.kind !== kind} onChange={() => setState((prev) => withKind(prev, kind))} />
                <KindIcon kind={kind} />
                <span>{kindLabel(kind)}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="ed-group">
          <legend>{tr("group.find")}</legend>
          <div className="form-grid">
            <Field className="full" label={tr("f.title")} problem={problems.title}>
              {(p) => <Input {...p} autoComplete="off" value={state.title} onChange={(e) => patch({ title: e.target.value })} />}
            </Field>
            <Field label={tr("f.workspace")} problem={problems.workspace ?? problems.workspace_id}>
              {(p) => (
                <Select
                  {...p}
                  value={state.workspaceId}
                  onChange={(e) => (e.target.value === NEW_WORKSPACE ? setWsOpen(true) : patch({ workspaceId: e.target.value }))}
                  options={[
                    ...(state.workspaceId === "" ? [{ value: "", label: tr("f.workspace.pick") }] : []),
                    ...workspaces.map((w) => ({ value: w.id, label: w.slug })),
                    { value: NEW_WORKSPACE, label: tr("f.workspace.new") },
                  ]}
                />
              )}
            </Field>
            <Field label={tr("f.category")} hint={tr("f.category.hint")} problem={problems.category}>
              {(p) => (
                <>
                  <Input {...p} list={categoriesId} autoComplete="off" value={state.category} onChange={(e) => patch({ category: e.target.value, categoryTouched: true })} />
                  <datalist id={categoriesId}>
                    {categories.map((c) => (
                      <option key={c} value={c} />
                    ))}
                  </datalist>
                </>
              )}
            </Field>
            <div className="field full">
              <span className="label" id={`${envId}-l`}>
                {tr("f.environment")}
              </span>
              <div className="ed-envs" role="radiogroup" aria-labelledby={`${envId}-l`}>
                {ENVIRONMENTS.map((env) => (
                  <label key={env}>
                    <input type="radio" name={envId} value={env} checked={state.environment === env} onChange={() => patch({ environment: env })} />
                    {env === "prod" ? <EnvBadge env="prod" /> : env}
                  </label>
                ))}
              </div>
              {state.environment === "prod" && <Notice tone="warn" title={tr("f.environment.prod")} />}
            </div>
            <div className="full">
              <RoleChips value={state.roleLabel} onChange={(roleLabel) => patch({ roleLabel })} problem={problems.role_label} />
            </div>
            <Field className="full" label={tr("f.target")} hint={tr("f.target.hint")} problem={problems.target}>
              {(p) => <Input {...p} mono value={state.target} onChange={(e) => patch({ target: e.target.value })} />}
            </Field>
            <Field className="full" label={tr("f.description")} hint={tr("f.description.hint")} problem={problems.description}>
              {(p) => <Textarea {...p} rows={3} value={state.description} onChange={(e) => patch({ description: e.target.value })} />}
            </Field>
            <Field label={tr("f.tags")} hint={tr("f.tags.hint")} problem={problems.tags}>
              {(p) => <Input {...p} autoComplete="off" value={state.tags} onChange={(e) => patch({ tags: e.target.value })} />}
            </Field>
            <Field label={session ? tr("ttl.session") : tr("f.expires")} problem={state.expiry === "date" ? undefined : problems.expires_at}>
              {(p) => <Select {...p} value={state.expiry} onChange={(e) => patch({ expiry: e.target.value })} options={expiryOptions} />}
            </Field>
            {state.expiry === "date" && (
              <Field label={tr("f.expires.date.label")} problem={problems.expires_at}>
                {(p) => <Input {...p} type="datetime-local" value={state.expiryDate} onChange={(e) => patch({ expiryDate: e.target.value })} />}
              </Field>
            )}
            <Field label={tr("f.maxUses")} hint={tr("f.maxUses.hint")} problem={problems.max_uses}>
              {(p) => <Input {...p} mono inputMode="numeric" value={state.maxUses} onChange={(e) => patch({ maxUses: e.target.value })} />}
            </Field>
          </div>
          {session && (
            <p className="small secondary ed-note">
              <Icon name="clock" /> {tr("ttl.sessionNote")}
            </p>
          )}
        </fieldset>

        {secretPanel}

        <div className="ed-savebar">
          <Button variant="ghost" onClick={() => navigate("~/vault")}>
            {tr("cancel")}
          </Button>
          <Button variant="primary" type="submit" loading={busy}>
            {tr("save")}
          </Button>
        </div>
      </div>

      <aside className={cx("ed-side")} aria-label={tr("side.ask")}>
        <Panel title={tr("side.ask")} icon="search">
          <div className="stack">
            <pre className="ed-pre">{`resolve {\n${ask.join("\n")}\n}`}</pre>
            <p className="small muted">{tr("side.askNote")}</p>
          </div>
        </Panel>
        <Panel title={tr("side.agents")} icon="bot">
          <p className="small secondary">{tr("side.agentsBody")}</p>
        </Panel>
      </aside>
      <WorkspaceDialog open={wsOpen} onOpenChange={setWsOpen} onCreated={(ws) => patch({ workspaceId: ws.id })} />
    </form>
  );
}
