import { t } from "../i18n";
import { formatLeft, useCountdown } from "../state/time";
import { cx } from "./cx";

export type TtlTone = "ok" | "low" | "critical" | "gate";

/** low at 25% or less, critical at 10% or less (tokens.json `behavior`). */
export function ttlTone(left: number, total: number): Exclude<TtlTone, "gate"> {
  const ratio = total > 0 ? left / total : 1;
  if (ratio <= 0.1) return "critical";
  if (ratio <= 0.25) return "low";
  return "ok";
}

interface TtlRingProps {
  /** Seconds in the whole span. */
  total: number;
  /** Seconds left now (static ring). Give `endsAt` instead for a ring that runs. */
  left?: number;
  /** Time the span ends, in ms since epoch. The ring ticks each second. */
  endsAt?: number;
  size?: 20 | 22 | 24 | 28 | 30 | 32;
  /** `gate` is the ink ring of the auto-lock timer. Other tones come from the time left. */
  gate?: boolean;
  /** Show the time inside the ring. */
  showLabel?: boolean;
  className?: string;
}

/** An SVG arc that starts at 12 o'clock. Pair it with text for anything that matters: colour is not the only signal. */
export function TtlRing({ total, left, endsAt, size = 24, gate = false, showLabel = false, className }: TtlRingProps) {
  const running = useCountdown(endsAt ?? null);
  const seconds = Math.max(0, Math.min(total, running ?? left ?? 0));
  const tone: TtlTone = gate ? "gate" : ttlTone(seconds, total);
  const stroke = Math.max(2, Math.round(size / 9));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const ratio = total > 0 ? seconds / total : 0;
  const label = seconds <= 0 && !gate ? t("ttl.expired") : t("ttl.left", { time: formatLeft(seconds) });
  return (
    <span className={cx("ttl", tone === "gate" ? "gate" : tone, className)} role="img" aria-label={label}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true" focusable="false">
        <circle className="track" cx={size / 2} cy={size / 2} r={radius} strokeWidth={stroke} />
        <circle
          className="val"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - ratio)}
        />
      </svg>
      {showLabel && (
        <span className="lbl" aria-hidden="true">
          {formatLeft(seconds)}
        </span>
      )}
    </span>
  );
}
