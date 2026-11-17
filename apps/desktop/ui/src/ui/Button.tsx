import { useCallback, useEffect, useRef, useState, type ComponentProps, type CSSProperties, type ReactNode } from "react";
import { cx } from "./cx";
import { Icon, type IconName } from "./Icon";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "danger-ghost";
export type ButtonSize = "sm" | "md" | "lg";

interface ButtonBase {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: IconName;
  /** Shows a spinner ring. The label stays, the button is not clickable. */
  loading?: boolean;
}

export type ButtonProps = ButtonBase & ComponentProps<"button">;

const classes = (variant: ButtonVariant, size: ButtonSize, extra?: string) =>
  cx("btn", variant !== "secondary" && variant, size !== "md" && size, extra);

/** One primary button per view. Labels say the action ("Save item"). */
export function Button({
  variant = "secondary",
  size = "md",
  icon,
  loading = false,
  className,
  children,
  disabled,
  type = "button",
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      className={classes(variant, size, className)}
      disabled={disabled}
      aria-busy={loading || undefined}
      {...rest}
      onClick={loading ? undefined : rest.onClick}
    >
      {loading ? <span className="spinner" aria-hidden="true" /> : icon && <Icon name={icon} />}
      {children}
    </button>
  );
}

interface IconButtonProps extends Omit<ButtonProps, "children" | "icon"> {
  icon: IconName;
  /** Names the action and the object: "Copy: Password". */
  label: string;
}

/** A button with an icon only. The label is the accessible name. */
export function IconButton({ icon, label, variant = "ghost", size = "md", className, ...rest }: IconButtonProps) {
  return (
    <button
      type="button"
      className={classes(variant, size, cx("icon-only", className))}
      aria-label={label}
      title={label}
      {...rest}
    >
      <Icon name={icon} />
    </button>
  );
}

interface HoldButtonProps extends Omit<ButtonBase, "loading"> {
  /** How long to hold, in ms. Reveal 500, approve 600, panic 1000 (tokens.json `motion.hold`). */
  holdMs: number;
  /** Runs when the hold ends. */
  onHold: () => void;
  /** Also run `onHold` on a plain pointer click. Never set it for panic or reveal: there the hold is the safety. */
  allowClick?: boolean;
  disabled?: boolean;
  className?: string;
  children?: ReactNode;
  /** For an icon-only hold button. */
  "aria-label"?: string;
  title?: string;
}

/**
 * Hold to confirm. A fill grows while the pointer, Space or Enter is held. Releasing early cancels.
 * Reduced motion shows the fill at once; the hold time stays (app.css).
 */
export function HoldButton({
  holdMs,
  onHold,
  allowClick = false,
  variant = "secondary",
  size = "md",
  icon,
  disabled,
  className,
  children,
  ...rest
}: HoldButtonProps) {
  const [holding, setHolding] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const done = useRef(false);
  const viaPointer = useRef(false);
  const latest = useRef(onHold);
  useEffect(() => {
    latest.current = onHold;
  });

  const cancel = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    setHolding(false);
  }, []);

  const start = useCallback(() => {
    if (disabled || timer.current) return;
    done.current = false;
    setHolding(true);
    timer.current = setTimeout(() => {
      timer.current = null;
      done.current = true;
      setHolding(false);
      latest.current();
    }, holdMs);
  }, [disabled, holdMs]);

  useEffect(() => cancel, [cancel]);

  const iconOnly = !children;
  return (
    <button
      type="button"
      disabled={disabled}
      className={classes(variant, size, cx("hold", holding && "holding", iconOnly && "icon-only", className))}
      style={{ "--hold-ms": `${holdMs}ms` } as CSSProperties}
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        viaPointer.current = true;
        start();
      }}
      onPointerUp={cancel}
      onPointerLeave={cancel}
      onPointerCancel={cancel}
      onKeyDown={(e) => {
        if ((e.key === " " || e.key === "Enter") && !e.repeat) {
          e.preventDefault();
          viaPointer.current = false;
          start();
        }
      }}
      onKeyUp={(e) => {
        if (e.key === " " || e.key === "Enter") cancel();
      }}
      onBlur={cancel}
      onClick={() => {
        if (allowClick && viaPointer.current && !done.current) onHold();
        viaPointer.current = false;
      }}
      {...rest}
    >
      {icon && <Icon name={icon} />}
      {children}
    </button>
  );
}
