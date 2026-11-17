import type { ReactNode } from "react";
import type { Environment, ItemKind } from "../bindings";
import { cx } from "./cx";
import { Icon, type IconName } from "./Icon";

/** `prod` is red with a triangle mark, so it reads without colour. Always the rightmost badge in a row. */
export function EnvBadge({ env }: { env: Environment }) {
  return <span className={cx("env", env)}>{env}</span>;
}

export const ROLE_PRESETS = ["admin", "normal user", "read-only", "SAI user"] as const;

interface RoleChipProps {
  role: string;
  /** Custom roles have a dashed outline. Presets are filled. */
  custom?: boolean;
}

export function RoleChip({ role, custom }: RoleChipProps) {
  const isCustom = custom ?? !(ROLE_PRESETS as readonly string[]).includes(role);
  return <span className={cx("chip", "role", isCustom && "custom")}>{role}</span>;
}

interface SelectableChipProps {
  children: ReactNode;
  pressed: boolean;
  onToggle: () => void;
  disabled?: boolean;
}

/** A chip you can press. Use several in a group for multi choice, or inside a radio group for one choice. */
export function SelectableChip({ children, pressed, onToggle, disabled }: SelectableChipProps) {
  return (
    <button type="button" className="chip" aria-pressed={pressed} onClick={onToggle} disabled={disabled}>
      {children}
    </button>
  );
}

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("chip", className)}>{children}</span>;
}

export type StatusTone = "ok" | "warn" | "bad" | "off";

/** Always next to a word: the dot colour only confirms it. */
export function StatusDot({ tone, children }: { tone: StatusTone; children: ReactNode }) {
  return <span className={cx("status", tone)}>{children}</span>;
}

/** Bot icon plus the agent name. It shows items an agent made (vault poisoning risk, T-9). */
export function AgentMadeBadge({ agent }: { agent: string }) {
  return (
    <span className="agent-made">
      <Icon name="bot" size={14} />
      {agent}
    </span>
  );
}

const KIND_ICONS: Record<ItemKind, IconName> = {
  web_login: "globe",
  api_key: "key",
  ssh_key: "terminal",
  session_token: "ticket",
  browser_session: "window",
  database: "database",
  cloud: "cloud",
  certificate: "cert",
  env_bundle: "braces",
  note: "note",
};

/** 30 px square with the icon of the item kind. A prod item gets a red border. */
export function KindIcon({ kind, prod }: { kind: ItemKind; prod?: boolean }) {
  return (
    <span className={cx("kind-ico", prod && "prod")}>
      <Icon name={KIND_ICONS[kind]} size={16} />
    </span>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd>{children}</kbd>;
}
