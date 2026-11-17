import { useEffect, useId, useState, type ReactNode } from "react";
import { useScreenT } from "../../i18n";
import { Button, cx, Icon, IconButton, Input, SelectableChip, Textarea } from "../../ui";
import { ROLE_PRESETS } from "../vault/kinds";
import { messages } from "./messages";
import { newPair, type Pair } from "./model";

/** Same limit as the secret field of the vault screen: a shown value hides again after 15 s. */
const SHOW_MS = 15_000;

interface ControlProps {
  id?: string;
  "aria-describedby"?: string;
  "aria-invalid"?: true;
}

interface SecretInputProps {
  /** Names the secret: "Password". Used in the button names. */
  label: string;
  value: string;
  onChange: (value: string) => void;
  multiline?: boolean;
  rows?: number;
  control?: ControlProps;
  /** Used when there is no visible label, for example inside a table row. */
  ariaLabel?: string;
  /** Extra buttons next to the eye button. */
  extra?: ReactNode;
}

/**
 * A masked text control with a show button. A shown value hides after 15 s and when the control unmounts.
 * The value lives in the form state only. It is never put in a title, a log or a URL.
 */
export function SecretInput({ label, value, onChange, multiline, rows = 4, control, ariaLabel, extra }: SecretInputProps) {
  const tr = useScreenT(messages);
  const [shown, setShown] = useState(false);
  useEffect(() => {
    if (!shown) return;
    const id = setTimeout(() => setShown(false), SHOW_MS);
    return () => clearTimeout(id);
  }, [shown]);

  const common = {
    ...control,
    "aria-label": control?.id ? undefined : ariaLabel,
    autoComplete: "off",
    spellCheck: false,
    value,
    onChange: (e: { target: { value: string } }) => onChange(e.target.value),
  };
  return (
    <div className="input-row">
      {multiline ? (
        <Textarea mono rows={rows} className={cx(!shown && "ed-masked")} {...common} />
      ) : (
        <Input mono type={shown ? "text" : "password"} {...common} />
      )}
      {extra}
      <IconButton
        icon={shown ? "eyeOff" : "eye"}
        label={shown ? tr("secret.hide", { label }) : tr("secret.show", { label })}
        aria-pressed={shown}
        onClick={() => setShown((s) => !s)}
      />
    </div>
  );
}

interface RoleChipsProps {
  value: string;
  onChange: (value: string) => void;
  problem?: string;
}

/** One role label: a preset chip, or a custom text. Pressing the chosen chip again clears it. */
export function RoleChips({ value, onChange, problem }: RoleChipsProps) {
  const tr = useScreenT(messages);
  const labelId = useId();
  const hintId = useId();
  const isPreset = (ROLE_PRESETS as readonly string[]).includes(value);
  return (
    <div className="field">
      <span className="label" id={labelId}>
        {tr("f.role")}
      </span>
      <div className="row-inline" role="group" aria-labelledby={labelId} aria-describedby={hintId}>
        {ROLE_PRESETS.map((role) => (
          <SelectableChip key={role} pressed={value === role} onToggle={() => onChange(value === role ? "" : role)}>
            {role}
          </SelectableChip>
        ))}
        <Input
          className="ed-role-input"
          placeholder={tr("f.role.custom")}
          aria-label={tr("f.role.custom")}
          aria-invalid={problem ? true : undefined}
          value={isPreset ? "" : value}
          onChange={(e) => onChange(e.target.value)}
        />
      </div>
      <span className="hint" id={hintId}>
        {tr("f.role.hint")}
      </span>
      {problem && (
        <span className="problem">
          <Icon name="alert" />
          {problem}
        </span>
      )}
    </div>
  );
}

interface PairsEditorProps {
  legend: string;
  pairs: readonly Pair[];
  onChange: (pairs: Pair[]) => void;
  /** The value is a secret: masked with a show button. */
  secret: boolean;
  /** Problems of the rows, shown below the rows. */
  problems?: readonly string[];
  /** Uppercase names, for environment variables. */
  upperNames?: boolean;
}

/** Name and value rows for env bundles, cloud extras and database parameters. */
export function PairsEditor({ legend, pairs, onChange, secret, problems = [], upperNames }: PairsEditorProps) {
  const tr = useScreenT(messages);
  const update = (id: number, patch: Partial<Pair>) => onChange(pairs.map((p) => (p.id === id ? { ...p, ...patch } : p)));
  return (
    <div className="field full">
      <span className="label">{legend}</span>
      <ul className="ed-pairs" aria-label={legend}>
        {pairs.map((pair, index) => (
          <li key={pair.id}>
            <Input
              mono
              aria-label={tr("pairs.rowName", { row: index + 1 })}
              placeholder={tr("pairs.name")}
              value={pair.name}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => update(pair.id, { name: upperNames ? e.target.value.toUpperCase() : e.target.value })}
            />
            {secret ? (
              <SecretInput label={pair.name || tr("pairs.value")} ariaLabel={tr("pairs.rowValue", { row: index + 1 })} value={pair.value} onChange={(value) => update(pair.id, { value })} />
            ) : (
              <Input mono aria-label={tr("pairs.rowValue", { row: index + 1 })} placeholder={tr("pairs.value")} value={pair.value} autoComplete="off" onChange={(e) => update(pair.id, { value: e.target.value })} />
            )}
            <IconButton icon="trash" label={pair.name ? tr("pairs.remove", { name: pair.name }) : tr("pairs.removeRow")} onClick={() => onChange(pairs.filter((p) => p.id !== pair.id))} />
          </li>
        ))}
      </ul>
      {problems.map((problem) => (
        <span className="problem" key={problem}>
          <Icon name="alert" />
          {problem}
        </span>
      ))}
      <Button size="sm" icon="plus" className="ed-add" onClick={() => onChange([...pairs, newPair()])}>
        {tr("pairs.add")}
      </Button>
    </div>
  );
}
