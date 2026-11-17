import type { ReactNode } from "react";
import { t } from "../i18n";

/**
 * Characters that change how text looks without being seen: bidi controls, zero-width characters, tag characters,
 * line and paragraph separators and any other control (general categories Cf, Zl, Zp, Cc). A line break and a tab
 * stay as they are.
 */
const INVISIBLE = /[\p{Cf}\p{Zl}\p{Zp}\p{Cc}]/u;

const isInvisible = (char: string): boolean => char !== "\n" && char !== "\t" && INVISIBLE.test(char);

const code = (char: string): string => `‹U+${(char.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}›`;

/** Cuts the text into runs of normal characters and single invisible characters. */
function runs(text: string): { text: string; hidden: boolean }[] {
  const out: { text: string; hidden: boolean }[] = [];
  for (const char of text) {
    const hidden = isInvisible(char);
    const last = out[out.length - 1];
    if (!hidden && last && !last.hidden) last.text += char;
    else out.push({ text: char, hidden });
  }
  return out;
}

/**
 * The text with each invisible character written as a visible code such as `‹U+202E›`. Use it where the text goes
 * into a translated sentence. The backend removes most of these characters already; this is the second layer, so
 * a reordering or a hidden character cannot pass unseen (AUD-24).
 */
export function showInvisible(text: string): string {
  return runs(text)
    .map((run) => (run.hidden ? code(run.text) : run.text))
    .join("");
}

function visible(text: string): ReactNode[] {
  return runs(text).map((run, index) =>
    run.hidden ? (
      <span key={index} className="invisible-char">
        {code(run.text)}
      </span>
    ) : (
      run.text
    ),
  );
}

/**
 * Text that an agent wrote. Dashed brass border, mono face, a fixed label. It is plain text only: React text,
 * never HTML (S-5, S-6). The backend already removed control characters and cut it to 500 characters. Invisible
 * and bidi characters show as codes, and the text is isolated (`bdi`), so it cannot reorder what is around it.
 */
export function UntrustedText({ text }: { text: string }) {
  return (
    <div className="untrusted" data-label={t("untrusted.label")} role="group" aria-label={t("untrusted.label")}>
      <div className="text" tabIndex={0}>
        <bdi>{visible(text)}</bdi>
      </div>
    </div>
  );
}

/** Short agent text inside a line (an agent name, an item title): isolated and with visible codes. */
export function InlineUntrusted({ text }: { text: string }) {
  return <bdi>{visible(text)}</bdi>;
}
