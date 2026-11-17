import type { ReactNode } from "react";
import { isIpcFailure, type UiError } from "../ipc/client";
import { hasMessage, t } from "../i18n";
import { Button } from "./Button";
import { GateMark } from "./GateMark";
import { Icon, type IconName } from "./Icon";
import { cx } from "./cx";

interface EmptyStateProps {
  /** The situation, not the missing thing: "The gate is ready". */
  title: string;
  /** Why this is fine, or what to do. */
  body: string;
  icon?: IconName;
  /** Use the gate mark instead of an icon. */
  gate?: boolean;
  /** One primary action. */
  action?: ReactNode;
  /** Numbered first steps. */
  steps?: readonly ReactNode[];
  /** `h1` for a whole page, `h2` inside a panel. */
  as?: "h1" | "h2";
}

export function EmptyState({ title, body, icon, gate, action, steps, as: Heading = "h2" }: EmptyStateProps) {
  return (
    <div className="state-block">
      {gate ? <GateMark size={56} /> : icon && <Icon name={icon} size={32} />}
      <Heading>{title}</Heading>
      <p>{body}</p>
      {steps && (
        <ol className="steps" aria-label={t("state.empty.firstSteps")}>
          {steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      )}
      {action && <div className="actions">{action}</div>}
    </div>
  );
}

/** The text a person reads for an error code. Falls back to the backend text, then to a generic line. */
export function errorText(error: UiError): string {
  const key = `error.code.${error.code}`;
  return hasMessage(key) ? t(key) : error.message ? asSentence(error.message) : t("error.code.fallback");
}

/** Backend messages are short lower-case phrases; the UI shows them as sentences next to its own text. */
function asSentence(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) return trimmed;
  const first = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(first) ? first : `${first}.`;
}

interface ErrorStateProps {
  /** What failed, as a verb phrase: "load items". The title reads "Cannot load items". */
  action: string;
  error: unknown;
  onRetry?: () => void;
  retrying?: boolean;
  as?: "h1" | "h2";
}

/** Title, what is safe, "Try again", and the mono code line `command: code`. */
export function ErrorState({ action, error, onRetry, retrying, as: Heading = "h2" }: ErrorStateProps) {
  const ui = isIpcFailure(error) ? error.error : null;
  return (
    <div className="state-block" role="alert">
      <Icon name="shieldAlert" size={32} />
      <Heading>{t("error.title", { action })}</Heading>
      <p>{ui ? errorText(ui) : t("error.code.fallback")} {t("error.body")}</p>
      {onRetry && (
        <div className="actions">
          <Button variant="primary" icon="refresh" onClick={onRetry} loading={retrying}>
            {t("error.retry")}
          </Button>
        </div>
      )}
      {ui && <p className="code">{t("error.line", { command: ui.command, code: ui.code })}</p>}
    </div>
  );
}

interface SkeletonProps {
  /** Names what loads. Read by screen readers. */
  label: string;
  rows?: number;
  variant?: "rows" | "block" | "line";
}

/** A loading placeholder. Shimmer is off with reduced motion. */
export function Skeleton({ label, rows = 4, variant = "rows" }: SkeletonProps) {
  return (
    <div role="status" aria-busy="true" aria-label={label} className={cx("skeleton", variant)}>
      {variant === "rows" &&
        Array.from({ length: rows }, (_, i) => (
          <div className="skel-row" key={i}>
            <span className="skel box" />
            <span className="skel line" />
          </div>
        ))}
      {variant === "block" && <span className="skel block" />}
      {variant === "line" && <span className="skel" />}
      <span className="sr-only">{label}</span>
    </div>
  );
}

/** A page-size loading state with turning rings. */
export function LoadingState({ label }: { label: string }) {
  return (
    <div className="state-block" role="status" aria-busy="true">
      <GateMark size={48} mode="spin" />
      <p>{label}</p>
    </div>
  );
}
