import { useId } from "react";
import { cx } from "./cx";
import "./gate-mark.css";

export type GateMode = "open" | "locked" | "spin";

interface GateMarkProps {
  size?: number;
  mode?: GateMode;
  className?: string;
}

const RINGS = [
  { r: 10.5, cls: "r1", gap: 0.12 },
  { r: 7.2, cls: "r2", gap: 0.16 },
  { r: 3.9, cls: "r3", gap: 0.24 },
] as const;

/** The five spectrum colors of the app (`--c-spectrum-*` in tokens.css; gate-mark.css sets each stop). Red bends least, violet most. */
const SPECTRUM = ["red", "amber", "green", "blue", "violet"] as const;

/**
 * The Cerberus gate: three gapped rings and a core, flat and solid in the current ink (white on dark, black on light;
 * see gate-mark.css), like the Vercel triangle. The one accent is the innermost ring, cut in sharp spectrum bands.
 * Open: the gaps line up at the bottom. Locked: closed rings, fully monochrome. Spin: the rings turn, the bands with them.
 * The dark tile of the app icon lives in public/cerberus-mark.svg; in the app the mark has no tile.
 */
export function GateMark({ size = 28, mode = "open", className }: GateMarkProps) {
  const uid = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const bands = `${uid}-bands`;
  const locked = mode === "locked";
  return (
    <svg
      className={cx("gate-mark", locked && "gate-mark--locked", mode === "spin" && "gate-mark--spin", className)}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      {!locked && (
        <defs>
          {/* Hard-edged bands across the innermost ring, tilted like a refracted beam. */}
          <linearGradient id={bands} gradientUnits="userSpaceOnUse" x1="8.15" y1="14.7" x2="15.85" y2="9.3">
            {SPECTRUM.flatMap((color, i) => [
              <stop key={`${color}-a`} className={`gate-mark__band gate-mark__band--${color}`} offset={i / SPECTRUM.length} />,
              <stop key={`${color}-b`} className={`gate-mark__band gate-mark__band--${color}`} offset={(i + 1) / SPECTRUM.length} />,
            ])}
          </linearGradient>
        </defs>
      )}
      {RINGS.map(({ r, cls, gap }) => {
        const len = 2 * Math.PI * r;
        const hole = locked ? 0 : len * gap;
        return (
          <circle
            key={cls}
            className={cx("gate-mark__ring", `gate-mark__ring--${cls}`)}
            cx="12"
            cy="12"
            r={r}
            fill="none"
            stroke={cls === "r3" && !locked ? `url(#${bands})` : "currentColor"}
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeDasharray={`${(len - hole).toFixed(2)} ${hole.toFixed(2)}`}
            strokeDashoffset={(0.75 * len - hole / 2).toFixed(2)}
          />
        );
      })}
      <circle cx="12" cy="12" r="1.4" fill="currentColor" />
    </svg>
  );
}
