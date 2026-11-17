import {
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { cx } from "./cx";
import { Icon } from "./Icon";

interface FieldProps {
  label: string;
  hint?: string;
  /** A problem text. It makes the control invalid and is read with the label. */
  problem?: string;
  /** Receives the props to spread on the control. */
  children: (control: { id: string; "aria-describedby"?: string; "aria-invalid"?: true }) => ReactNode;
  className?: string;
}

/** Label, control, hint and problem text, wired together. */
export function Field({ label, hint, problem, children, className }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const problemId = `${id}-problem`;
  const describedBy = [hint && hintId, problem && problemId].filter(Boolean).join(" ") || undefined;
  return (
    <div className={cx("field", className)}>
      <label htmlFor={id}>{label}</label>
      {children({ id, "aria-describedby": describedBy, ...(problem ? { "aria-invalid": true as const } : {}) })}
      {hint && (
        <span id={hintId} className="hint">
          {hint}
        </span>
      )}
      {problem && (
        <span id={problemId} className="problem">
          <Icon name="alert" />
          {problem}
        </span>
      )}
    </div>
  );
}

type InputProps = InputHTMLAttributes<HTMLInputElement> & { mono?: boolean; large?: boolean };

export function Input({ mono, large, className, ...rest }: InputProps) {
  return <input className={cx("input", mono && "mono", large && "lg", className)} {...rest} />;
}

export function Textarea({ mono, className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }) {
  return <textarea className={cx("input", mono && "mono", className)} {...rest} />;
}

export interface SelectOption {
  value: string;
  label: string;
}

type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "children"> & { options: readonly SelectOption[] };

/** A native select: it is keyboard and screen reader complete, and it follows the OS popup. */
export function Select({ options, className, ...rest }: SelectProps) {
  return (
    <select className={cx("input", "select", className)} {...rest}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

interface ToggleProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "children"> {
  /** The setting name. It is the accessible name. */
  label: string;
  hint?: string;
}

/** A real `input[type=checkbox]` styled as a switch. Disabled switches should say why next to them ("Owner only"). */
export function Switch({ label, hint, className, ...rest }: ToggleProps) {
  return (
    <label className={cx("switch", className)}>
      <input type="checkbox" role="switch" {...rest} />
      <span>
        {label}
        {hint && <span className="hint block">{hint}</span>}
      </span>
    </label>
  );
}

export function Checkbox({ label, hint, className, ...rest }: ToggleProps) {
  return (
    <label className={cx("check", className)}>
      <input type="checkbox" {...rest} />
      <span>
        {label}
        {hint && <span className="hint block">{hint}</span>}
      </span>
    </label>
  );
}

interface SegmentedProps<V extends string> {
  label: string;
  value: V;
  onChange: (value: V) => void;
  options: readonly { value: V; label: string }[];
  size?: "sm" | "lg";
}

/** Single choice from a few options. Radio semantics: one pressed, arrow keys move and select. */
export function SegmentedControl<V extends string>({ label, value, onChange, options, size = "sm" }: SegmentedProps<V>) {
  const move = (group: HTMLElement | null, index: number, delta: number) => {
    const next = options[(index + delta + options.length) % options.length];
    if (!next) return;
    onChange(next.value);
    queueMicrotask(() => group?.querySelector<HTMLElement>(`[data-value="${next.value}"]`)?.focus());
  };
  return (
    <div className={cx("seg", size === "lg" && "lg")} role="radiogroup" aria-label={label}>
      {options.map((o, i) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          tabIndex={o.value === value ? 0 : -1}
          onClick={() => onChange(o.value)}
          data-value={o.value}
          onKeyDown={(e) => {
            const delta = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
            if (delta === 0) return;
            e.preventDefault();
            move(e.currentTarget.parentElement, i, delta);
          }}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
