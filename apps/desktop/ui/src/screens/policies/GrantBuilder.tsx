import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import type { AgentView_Serialize, DayOfWeek, Environment, GrantMode, ItemKind, Permission, WorkspaceView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { useQueryClient } from "@tanstack/react-query";
import { useCan } from "../../state/session";
import { Button, Checkbox, Field, Input, Notice, Panel, SelectableChip, Switch, useToast, errorText } from "../../ui";
import { grantsKey } from "../agents/queries";
import { draftToInput, emptyDraft, type Draft } from "./draft";
import { CATEGORIES, DAYS, ENVIRONMENTS, KINDS, MODES, PERMISSIONS, ROLE_LABELS } from "./labels";
import { messages } from "./messages";
import { simKey } from "./queries";

const MULTI = "__multi";

interface SlotProps {
  label: string;
  values: readonly string[];
  options: readonly { value: string; label: string }[];
  any: string;
  multiLabel: string;
  disabled: boolean;
  onChange: (values: string[]) => void;
  selectRef?: React.Ref<HTMLSelectElement>;
}

/** A select inside the sentence. It holds one choice; a saved grant with several shows "several" until changed. */
function Slot({ label, values, options, any, multiLabel, disabled, onChange, selectRef }: SlotProps) {
  const id = useId();
  const value = values.length > 1 ? MULTI : (values[0] ?? "");
  return (
    <>
      <label className="sr-only" htmlFor={id}>{label}</label>
      <select id={id} ref={selectRef} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value === "" || e.target.value === MULTI ? [] : [e.target.value])}>
        {any && <option value="">{any}</option>}
        {values.length > 1 && <option value={MULTI} disabled>{multiLabel}</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </>
  );
}

function ModeRadios({ value, onChange, disabled }: { value: GrantMode; onChange: (m: GrantMode) => void; disabled: boolean }) {
  const s = useScreenT(messages);
  const group = useRef<HTMLSpanElement>(null);
  const move = (e: KeyboardEvent) => {
    const delta = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (!delta) return;
    e.preventDefault();
    const next = MODES[(MODES.indexOf(value) + delta + MODES.length) % MODES.length];
    if (!next) return;
    onChange(next);
    queueMicrotask(() => group.current?.querySelector<HTMLElement>(`[data-mode="${next}"]`)?.focus());
  };
  return (
    <span className="modes" role="radiogroup" aria-label={s("builder.modes")} ref={group} onKeyDown={move}>
      {MODES.map((m) => (
        <button
          key={m}
          type="button"
          role="radio"
          aria-checked={m === value}
          tabIndex={m === value ? 0 : -1}
          data-mode={m}
          className={m === "deny" ? "block" : undefined}
          disabled={disabled}
          onClick={() => onChange(m)}
        >
          {s(`mode.${m}`)}
        </button>
      ))}
    </span>
  );
}

interface BuilderProps {
  agent: AgentView_Serialize;
  workspaces: readonly WorkspaceView[];
  draft: Draft;
  setDraft: (next: Draft) => void;
  canEdit: boolean;
  /** Move focus to the first choice (deep link `?new=1`). */
  focusOnMount: boolean;
}

const toggle = <T,>(list: readonly T[], item: T): T[] => (list.includes(item) ? list.filter((x) => x !== item) : [...list, item]);

/** The sentence builder: "QA runner can read items in workspace X, env staging, category Web login, and I approve: never." */
export function GrantBuilder({ agent, workspaces, draft, setDraft, canEdit, focusOnMount }: BuilderProps) {
  const s = useScreenT(messages);
  const isOwner = useCan("owner");
  const toast = useToast();
  const queryClient = useQueryClient();
  const [failure, setFailure] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const first = useRef<HTMLSelectElement>(null);
  const editing = draft.id !== null;
  const disabled = !canEdit;
  const set = (patch: Partial<Draft>) => setDraft({ ...draft, ...patch });

  useEffect(() => {
    if (focusOnMount) first.current?.focus();
  }, [focusOnMount]);

  const permValue = draft.permissions.length > 1 ? MULTI : (draft.permissions[0] ?? "read");
  const prodRule = (draft.environments.length === 0 || draft.environments.includes("prod")) && draft.mode === "auto";

  const save = async () => {
    if (draft.permissions.length === 0) {
      setProblem(s("save.perm"));
      return;
    }
    setProblem(null);
    setFailure(null);
    setBusy(true);
    try {
      await ipc.grantPut(draftToInput(agent.id, draft));
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: grantsKey(agent.id) }),
        queryClient.invalidateQueries({ queryKey: simKey(agent.id) }),
      ]);
      toast.push({ tone: "success", title: s("saved") });
      setDraft(emptyDraft());
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy(false);
    }
  };

  const ui = isIpcFailure(failure) ? failure.error : null;

  return (
    <Panel icon="shield" title={s(editing ? "builder.title.edit" : "builder.title")}>
      <div className="stack builder">
        {!canEdit && <Notice tone="info" title={s("viewer")} />}
        <p className="sentence">
          <span className="slot">{agent.name}</span> {s("builder.can")}{" "}
          <label className="sr-only" htmlFor="slot-permission">{s("builder.permission")}</label>
          <select
            id="slot-permission"
            value={permValue}
            disabled={disabled}
            onChange={(e) => e.target.value !== MULTI && set({ permissions: [e.target.value as Permission] })}
          >
            {draft.permissions.length > 1 && <option value={MULTI} disabled>{draft.permissions.map((p) => s(`perm.${p}`)).join(", ")}</option>}
            {PERMISSIONS.map((p) => (
              <option key={p} value={p}>{s(`perm.${p}`)}</option>
            ))}
          </select>{" "}
          {s("builder.items")}{" "}
          <Slot
            label={s("builder.workspace")}
            values={draft.workspaceIds}
            options={workspaces.map((w) => ({ value: w.id, label: w.slug }))}
            any={s("builder.anyWorkspace")}
            multiLabel={draft.workspaceIds.map((id) => workspaces.find((w) => w.id === id)?.slug ?? id).join(", ")}
            disabled={disabled}
            onChange={(workspaceIds) => set({ workspaceIds })}
            selectRef={first}
          />
          , {s("builder.env")}{" "}
          <Slot
            label={s("builder.environment")}
            values={draft.environments}
            options={ENVIRONMENTS.map((e) => ({ value: e, label: e }))}
            any={s("builder.anyEnv")}
            multiLabel={draft.environments.join(", ")}
            disabled={disabled}
            onChange={(environments) => set({ environments: environments as Environment[] })}
          />
          , {s("builder.category")}{" "}
          <Slot
            label={s("builder.categoryLabel")}
            values={draft.categories}
            options={CATEGORIES.map((c) => ({ value: c, label: c }))}
            any={s("builder.anyCategory")}
            multiLabel={draft.categories.join(", ")}
            disabled={disabled}
            onChange={(categories) => set({ categories })}
          />
          , {s("builder.approve")} <ModeRadios value={draft.mode} onChange={(mode) => set({ mode })} disabled={disabled} />
        </p>
        <p className="small muted" id="mode-help" aria-live="polite">{s(`mode.help.${draft.mode}`)}</p>

        {prodRule && (
          <Notice tone="warn" title={s("prod.title")}>
            {s("prod.body")}
            <div className="prod-switch">
              <Switch
                label={s("prod.switch")}
                hint={isOwner ? undefined : s("prod.ownerOnly")}
                checked={draft.prodAuto}
                disabled={disabled || !isOwner}
                onChange={(e) => set({ prodAuto: e.target.checked })}
              />
            </div>
          </Notice>
        )}

        <details>
          <summary>{s("narrow.summary")}</summary>
          <div className="stack narrow">
            <p className="small muted">{s("narrow.hint")}</p>
            <div role="group" aria-label={s("narrow.kinds")}>
              <span className="label small">{s("narrow.kinds")}</span>
              <div className="chips">
                {KINDS.map((k) => (
                  <SelectableChip key={k} pressed={draft.kinds.includes(k)} disabled={disabled} onToggle={() => set({ kinds: toggle<ItemKind>(draft.kinds, k) })}>
                    {s(`kind.${k}`)}
                  </SelectableChip>
                ))}
              </div>
            </div>
            <div role="group" aria-label={s("narrow.roles")}>
              <span className="label small">{s("narrow.roles")}</span>
              <div className="chips">
                {ROLE_LABELS.map((r) => (
                  <SelectableChip key={r} pressed={draft.roleLabels.includes(r)} disabled={disabled} onToggle={() => set({ roleLabels: toggle(draft.roleLabels, r) })}>
                    {r}
                  </SelectableChip>
                ))}
              </div>
            </div>
            <Field label={s("narrow.tags")} hint={s("narrow.tags.hint")}>
              {(p) => <Input {...p} value={draft.tags} disabled={disabled} onChange={(e) => set({ tags: e.target.value })} autoComplete="off" />}
            </Field>
          </div>
        </details>

        <details>
          <summary>{s("cond.summary")}</summary>
          <div className="cond">
            <div className="field full-row">
              <Switch label={s("cond.window")} checked={draft.windowOn} disabled={disabled} onChange={(e) => set({ windowOn: e.target.checked })} />
              {draft.windowOn && (
                <div className="stack window-fields">
                  <div role="group" aria-label={s("cond.days")} className="chips">
                    {DAYS.map((d: DayOfWeek) => (
                      <SelectableChip key={d} pressed={draft.days.includes(d)} disabled={disabled} onToggle={() => set({ days: toggle(draft.days, d) })}>
                        {s(`day.${d}`)}
                      </SelectableChip>
                    ))}
                  </div>
                  <div className="cond">
                    <Field label={s("cond.start")}>{(p) => <Input {...p} type="time" value={draft.start} disabled={disabled} onChange={(e) => set({ start: e.target.value })} />}</Field>
                    <Field label={s("cond.end")}>{(p) => <Input {...p} type="time" value={draft.end} disabled={disabled} onChange={(e) => set({ end: e.target.value })} />}</Field>
                    <Field label={s("cond.tz")}>{(p) => <Input {...p} mono value={draft.tz} disabled={disabled} onChange={(e) => set({ tz: e.target.value })} />}</Field>
                  </div>
                </div>
              )}
            </div>
            <Field label={s("cond.reads")} hint={s("cond.reads.hint")}>
              {(p) => <Input {...p} inputMode="numeric" value={draft.reads} disabled={disabled} onChange={(e) => set({ reads: e.target.value.replace(/\D/g, "") })} />}
            </Field>
            <Field label={s("cond.ends")} hint={s("cond.ends.hint")}>
              {(p) => <Input {...p} type="date" value={draft.ends} disabled={disabled} onChange={(e) => set({ ends: e.target.value })} />}
            </Field>
            <div className="field">
              <Checkbox label={s("cond.reason")} hint={s("cond.reason.hint")} checked={draft.reason} disabled={disabled} onChange={(e) => set({ reason: e.target.checked })} />
            </div>
          </div>
        </details>

        {problem && <Notice tone="warn" title={problem} />}
        {failure !== null && (
          <Notice tone="bad" title={s("save.failed")}>
            {ui ? errorText(ui) : null}
            {ui && <span className="block code-line mono small">{ui.command}: {ui.code}</span>}
          </Notice>
        )}
        {canEdit && (
          <div className="row-inline">
            <Button variant="primary" icon="check" loading={busy} onClick={() => void save()}>
              {s("save")}
            </Button>
            <Button variant="ghost" onClick={() => { setDraft(emptyDraft()); setProblem(null); setFailure(null); }}>
              {s(editing ? "cancelEdit" : "reset")}
            </Button>
          </div>
        )}
      </div>
    </Panel>
  );
}
