import { useState } from "react";
import type { CharClass } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { Button, Checkbox, errorText, useToast } from "../../ui";
import { messages } from "./messages";

const CLASSES: readonly { id: CharClass; label: "gen.lower" | "gen.upper" | "gen.digits" | "gen.symbols" }[] = [
  { id: "lower", label: "gen.lower" },
  { id: "upper", label: "gen.upper" },
  { id: "digits", label: "gen.digits" },
  { id: "symbols", label: "gen.symbols" },
];

interface Props {
  id: string;
  /** Receives the new password. It goes straight into the form field. */
  onGenerated: (password: string) => void;
}

/** The options of `password_generate`. The backend makes the password; the panel only asks. */
export function PasswordGenerator({ id, onGenerated }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const [length, setLength] = useState(24);
  const [classes, setClasses] = useState<ReadonlySet<CharClass>>(new Set<CharClass>(["lower", "upper", "digits", "symbols"]));
  const [busy, setBusy] = useState(false);

  const toggle = (c: CharClass) =>
    setClasses((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });

  const run = async () => {
    setBusy(true);
    try {
      onGenerated(await ipc.passwordGenerate(length, [...classes]));
      toast.push({ tone: "success", title: tr("gen.done") });
    } catch (error) {
      toast.push({ tone: "error", title: tr("gen.fail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="ed-gen" id={id}>
      <div className="between">
        <label htmlFor={`${id}-len`}>{tr("gen.length")}</label>
        <output htmlFor={`${id}-len`} className="num">
          {length}
        </output>
      </div>
      <input id={`${id}-len`} type="range" min={8} max={128} value={length} onChange={(e) => setLength(Number(e.target.value))} />
      <div className="row-inline" role="group" aria-label={tr("gen.classes")}>
        {CLASSES.map((c) => (
          <Checkbox key={c.id} label={tr(c.label)} checked={classes.has(c.id)} onChange={() => toggle(c.id)} />
        ))}
      </div>
      {classes.size === 0 && <p className="small muted">{tr("gen.needClass")}</p>}
      <Button size="sm" className="ed-gen-run" loading={busy} disabled={classes.size === 0} onClick={() => void run()}>
        {tr("gen.run")}
      </Button>
    </div>
  );
}
