import { cx } from "./cx";

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

/**
 * Three rings with a gap each. Open: the gaps line up at the bottom (the gate is open). Locked: closed rings.
 * Spin: the rings turn (loading). Reduced motion stops the turn (app.css).
 */
export function GateMark({ size = 28, mode = "open", className }: GateMarkProps) {
  return (
    <svg
      className={cx("gate", mode === "locked" && "is-locked", mode === "spin" && "spinning", className)}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      {RINGS.map(({ r, cls, gap }) => {
        const len = 2 * Math.PI * r;
        const hole = mode === "locked" ? 0 : len * gap;
        return (
          <circle
            key={cls}
            className={cls}
            cx="12"
            cy="12"
            r={r}
            strokeWidth="1.6"
            strokeDasharray={`${(len - hole).toFixed(2)} ${hole.toFixed(2)}`}
            strokeDashoffset={(0.75 * len - hole / 2).toFixed(2)}
          />
        );
      })}
      <circle className="core" cx="12" cy="12" r="1.4" />
    </svg>
  );
}
