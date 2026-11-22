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

/** A uniform random integer in [0, max), from the Web Crypto RNG (rejection sampling, no modulo bias). */
function randomBelow(max: number): number {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % max;
}

/**
 * Picks the 1-based numbers of the groups the person must type back, in ascending order. The draw is new for each
 * key, so the check does not always ask for the same places. Group 1 is left out when the key has a fixed prefix
 * (`CRK1`), because typing it proves nothing. A key with fewer groups than `count` checks all its groups.
 */
export function pickCheckGroups(groups: readonly string[], count = 2): number[] {
  const first = groups.length > count && /^CRK\d+$/i.test(groups[0] ?? "") ? 2 : 1;
  const pool = Array.from({ length: Math.max(0, groups.length - first + 1) }, (_, i) => i + first);
  const picked: number[] = [];
  while (picked.length < count && pool.length > 0) picked.push(...pool.splice(randomBelow(pool.length), 1));
  return picked.sort((a, b) => a - b);
}

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
