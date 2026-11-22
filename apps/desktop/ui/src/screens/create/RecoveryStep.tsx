import { useState } from "react";
import { ipc } from "../../ipc/client";
import { useScreenT } from "../../i18n";
import { Button, Checkbox, Field, Input, Notice, useToast, type IconName } from "../../ui";
import { CLIPBOARD_CLEAR_SECONDS } from "../../ui";
import { RecoveryKeyGrid, pickCheckGroups, recoveryGroups, sameGroup } from "./RecoveryKeyGrid";
import { messages } from "./messages";

interface ProofProps {
  recoveryKey: string;
  /** The one action that closes the step. It works only after the check. */
  action: { label: string; icon: IconName; loading: boolean; onRun: () => void };
  /** A quieter way out, on the left of the action. It works only after the check too. */
  secondary?: { label: string; onRun: () => void };
  /** How "Copy" copies the key. Default: the one-time value of the local vault (`clipboard_copy_once`). */
  copy?: () => Promise<unknown>;
}

/**
 * The key, print and copy, the warning, and the check: two random groups typed back and a "stored away" box. The key is a
 * prop from the caller; this part keeps only what the person types to check it.
 */
export function RecoveryProof({ recoveryKey, action, secondary, copy: copyKey }: ProofProps) {
  const t = useScreenT(messages);
  const toast = useToast();
  const groups = recoveryGroups(recoveryKey);
  // Two random groups, drawn once when the step mounts, so the check is not always the same places.
  const [checks] = useState(() => pickCheckGroups(groups));
  const [typed, setTyped] = useState<Record<number, string>>({});
  const [touched, setTouched] = useState(false);
  const [stored, setStored] = useState(false);
  const [copying, setCopying] = useState(false);

  const wrong = (n: number) => !sameGroup(typed[n] ?? "", groups[n - 1]);
  const ready = stored && checks.every((n) => !wrong(n));

  const copy = async () => {
    setCopying(true);
    try {
      await (copyKey ? copyKey() : ipc.clipboardCopyOnce("recovery_key"));
      toast.push({ tone: "success", title: t("recovery.copied"), detail: t("recovery.copied.detail"), ringSeconds: CLIPBOARD_CLEAR_SECONDS });
    } catch {
      toast.push({ tone: "error", title: t("recovery.copy.error") });
    } finally {
      setCopying(false);
    }
  };

  return (
    <>
      <RecoveryKeyGrid recoveryKey={recoveryKey} />
      <div className="row-inline">
        <Button icon="download" onClick={() => window.print()}>
          {t("recovery.print")}
        </Button>
        <Button icon="copy" loading={copying} onClick={() => void copy()}>
          {t("recovery.copy")}
        </Button>
      </div>
      <Notice tone="warn" title={t("recovery.warn.title")}>
        {t("recovery.warn.body")}
      </Notice>
      <div className="form-grid">
        {checks.map((n) => (
          <Field key={n} label={t("recovery.confirm.group", { n })} {...(touched && wrong(n) ? { problem: t("recovery.confirm.problem", { n }) } : {})}>
            {(control) => (
              <Input
                {...control}
                mono
                maxLength={8}
                autoComplete="off"
                spellCheck={false}
                value={typed[n] ?? ""}
                onChange={(e) => setTyped((prev) => ({ ...prev, [n]: e.target.value }))}
              />
            )}
          </Field>
        ))}
      </div>
      <Checkbox label={t("recovery.stored")} checked={stored} onChange={(e) => setStored(e.target.checked)} />
      <div className="nav-row">
        {secondary ? (
          <Button
            variant="ghost"
            size="lg"
            aria-disabled={!ready}
            onClick={() => {
              if (ready) secondary.onRun();
              else setTouched(true);
            }}
          >
            {secondary.label}
          </Button>
        ) : (
          <span />
        )}
        <Button
          variant="primary"
          size="lg"
          icon={action.icon}
          loading={action.loading}
          aria-disabled={!ready}
          onClick={() => {
            if (ready) action.onRun();
            else setTouched(true);
          }}
        >
          {action.label}
        </Button>
      </div>
    </>
  );
}

interface Props {
  recoveryKey: string;
  opening: boolean;
  onOpen: () => void;
}

/** Shows the recovery key once. The key is a prop from the wizard. */
export function RecoveryStep({ recoveryKey, opening, onOpen }: Props) {
  const t = useScreenT(messages);
  return (
    <section className="pane" aria-labelledby="create-h">
      <h1 id="create-h" tabIndex={-1} className="print-keep">
        {t("recovery.title")}
      </h1>
      <p className="lede">{t("recovery.lede")}</p>
      <RecoveryProof recoveryKey={recoveryKey} action={{ label: t("recovery.open"), icon: "unlock", loading: opening, onRun: onOpen }} />
    </section>
  );
}
