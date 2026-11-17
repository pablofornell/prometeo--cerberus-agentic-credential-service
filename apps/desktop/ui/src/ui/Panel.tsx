import { useId, type ReactNode } from "react";
import { cx } from "./cx";
import { Icon, type IconName } from "./Icon";

interface PanelProps {
  title: string;
  icon?: IconName;
  actions?: ReactNode;
  /** No body padding: for lists and tables that touch the edges. */
  flush?: boolean;
  children: ReactNode;
  className?: string;
}

/** A header rule and a quiet body. Not a card grid. The title is an h2. */
export function Panel({ title, icon, actions, flush, children, className }: PanelProps) {
  const id = useId();
  return (
    <section className={cx("panel", flush && "flush", className)} aria-labelledby={id}>
      <header>
        {icon && <Icon name={icon} />}
        <h2 id={id}>{title}</h2>
        {actions && <div className="actions">{actions}</div>}
      </header>
      <div className="body">{children}</div>
    </section>
  );
}

export type NoticeTone = "info" | "ok" | "warn" | "bad" | "neutral";

const NOTICE_ICON: Record<NoticeTone, IconName> = {
  info: "info",
  ok: "checkCircle",
  warn: "alert",
  bad: "shieldAlert",
  neutral: "info",
};

interface NoticeProps {
  tone?: NoticeTone;
  /** One bold sentence. */
  title: string;
  children?: ReactNode;
  /** Up to two buttons. */
  actions?: ReactNode;
  onDismiss?: () => void;
  dismissLabel?: string;
}

/** `role="alert"` only for `bad` (integrity and other loud problems). The rest is read in order. */
export function Notice({ tone = "neutral", title, children, actions, onDismiss, dismissLabel = "Dismiss" }: NoticeProps) {
  return (
    <div className={cx("notice", tone !== "neutral" && tone)} role={tone === "bad" ? "alert" : undefined}>
      <Icon name={NOTICE_ICON[tone]} />
      <div className="grow">
        <strong>{title}</strong> {children}
      </div>
      {actions}
      {onDismiss && (
        <button type="button" className="btn sm ghost icon-only" aria-label={dismissLabel} onClick={onDismiss}>
          <Icon name="x" />
        </button>
      )}
    </div>
  );
}
