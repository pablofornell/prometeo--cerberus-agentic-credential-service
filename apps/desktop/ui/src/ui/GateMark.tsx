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
  { r: 10.25, cls: "r1", gap: 0.12 },
  { r: 7.25, cls: "r2", gap: 0.16 },
  { r: 4.25, cls: "r3", gap: 0.24 },
] as const;

/** The core: a solid disc, the one place the mark carries colour. */
const CORE_R = 2.5;

/** Position in user units, rounded so the markup stays short. */
const pos = (v: number, origin = 12) => +(origin + v * CORE_R).toFixed(2);

/**
 * The five spectrum colors of the app (`--c-spectrum-*` in tokens.css; gate-mark.css sets each stop and fill).
 * Positions are in units of the core radius, from the center of the core. Each color is a soft radial pool that fades
 * out toward the next, so several hues are visible at once; the base disc under them is the cool end of the spectrum.
 */
const POOLS = [
  { color: "red", x: -0.7, y: -0.7, r: 1.8 },
  { color: "amber", x: -0.95, y: 0.45, r: 1.6 },
  { color: "green", x: -0.05, y: 1.0, r: 1.6 },
  { color: "blue", x: 0.95, y: 0.35, r: 1.5 },
  { color: "violet", x: 0.55, y: -0.8, r: 1.5 },
] as const;

/**
 * The Cerberus gate: three gapped rings and a core. The rings are flat and solid in the current ink (white on dark,
 * black on light; see gate-mark.css), like the Vercel triangle; the core is the one accent, a crisp disc filled with an
 * aurora of the five spectrum colors. No glow or halo outside the disc.
 * Open: the gaps line up at the bottom. Locked: closed rings and a flat grey core. Spin: the rings turn and the aurora
 * drifts inside the core.
 * The dark tile of the app icon lives in public/cerberus-mark.svg; in the app the mark has no tile.
 */
export function GateMark({ size = 28, mode = "open", className }: GateMarkProps) {
  const uid = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const clip = `${uid}-core`;
  const locked = mode === "locked";
  return (
    <svg
      className={cx("gate-mark", locked && "gate-mark--locked", mode === "spin" && "gate-mark--spin", className)}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      focusable="false"
    >
      {!locked && (
        <defs>
          <clipPath id={clip}>
            <circle cx="12" cy="12" r={CORE_R} />
          </clipPath>
          {POOLS.map(({ color, x, y, r }) => (
            <radialGradient key={color} id={`${uid}-${color}`} gradientUnits="userSpaceOnUse" cx={pos(x)} cy={pos(y)} r={pos(r, 0)}>
              <stop className={`gate-mark__hue gate-mark__hue--${color}`} offset="0" stopOpacity="1" />
              <stop className={`gate-mark__hue gate-mark__hue--${color}`} offset="0.35" stopOpacity="0.9" />
              <stop className={`gate-mark__hue gate-mark__hue--${color}`} offset="1" stopOpacity="0" />
            </radialGradient>
          ))}
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
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeDasharray={`${(len - hole).toFixed(2)} ${hole.toFixed(2)}`}
            strokeDashoffset={(0.75 * len - hole / 2).toFixed(2)}
          />
        );
      })}
      {locked ? (
        <circle cx="12" cy="12" r={CORE_R} fill="currentColor" />
      ) : (
        <g clipPath={`url(#${clip})`}>
          <circle className="gate-mark__base" cx="12" cy="12" r={CORE_R} />
          <g className="gate-mark__aurora">
            {POOLS.map(({ color }) => (
              <circle key={color} cx="12" cy="12" r={CORE_R * 2.4} fill={`url(#${uid}-${color})`} />
            ))}
          </g>
        </g>
      )}
    </svg>
  );
}
