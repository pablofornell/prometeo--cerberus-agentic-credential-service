import { useScreenT } from "../../i18n";
import { messages } from "./messages";
import "./recovery.css";

/** Splits a recovery key into its groups. Dashes or spaces separate them; a key with no separator is cut in fours. */
export function recoveryGroups(key: string): string[] {
  const text = key.trim();
  const parts = text.split(/[\s-]+/).filter(Boolean);
  if (parts.length > 1) return parts;
  return text.match(/.{1,4}/g) ?? [];
}

/** True when the typed text equals the group, ignoring case and spaces. */
export const sameGroup = (typed: string, group: string | undefined): boolean =>
  group !== undefined && typed.replace(/\s/g, "").toUpperCase() === group.toUpperCase();

/**
 * The numbered groups of a recovery key (mono). The text lives only in the props of the parent. It is never put
 * in `title` or `aria-label`. `print-area` is the only part the print style keeps.
 */
export function RecoveryKeyGrid({ recoveryKey }: { recoveryKey: string }) {
  const t = useScreenT(messages);
  const groups = recoveryGroups(recoveryKey);
  return (
    <div className="print-area">
      <p className="print-only">{t("recovery.print.title")}</p>
      <ol className="rk" aria-label={t("recovery.group", { count: groups.length })}>
        {groups.map((group, i) => (
          <li key={i}>
            <small aria-hidden="true">{i + 1}</small>
            <span>{group}</span>
          </li>
        ))}
      </ol>
      <p className="print-only">{t("recovery.print.note")}</p>
    </div>
  );
}
