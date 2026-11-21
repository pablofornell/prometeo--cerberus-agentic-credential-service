import { t } from "../i18n";
import type { IconName } from "../ui";
import { SCREENS, type ScreenDef } from "./screens";

export type CommandGroup = "goto" | "create" | "vault" | "view" | "items" | "agents";

export interface Command {
  id: string;
  group: CommandGroup;
  label: string;
  icon: IconName;
  /** Key caps shown at the right. */
  keys?: readonly string[];
  danger?: boolean;
  /** Extra words the filter matches. */
  keywords?: string;
  run: () => void;
}

export interface CommandContext {
  navigate: (to: string) => void;
  lock: () => void;
  panic: () => void;
  verifyAudit: () => void;
  exportCa: () => void;
  createBackup: () => void;
  cycleTheme: () => void;
  showShortcuts: () => void;
  themeLabel: string;
  /** Remote mode (ADR-0034): `lock` disconnects, panic acts on the server vault, local-only actions are left out. */
  remote: boolean;
}

/** Palette actions that need the local vault or this device (agent create, CSV import, connect guide, audit verify,
 *  CA export, backup). In remote mode they answer `remote_unsupported`, so the palette leaves them out (DEC-RM-11). */
const LOCAL_ONLY: ReadonlySet<string> = new Set(["new-agent", "import-csv", "connect", "verify", "export-ca", "backup"]);

const goTo = (s: ScreenDef) => s.layout === "app";

/** The static actions of the palette (IA section 6). Item and agent results are added by the palette. */
export function buildCommands(ctx: CommandContext): Command[] {
  const go: Command[] = SCREENS.filter(goTo).map((s) => ({
    id: `go-${s.id}`,
    group: "goto",
    label: t("palette.go", { screen: t(`screen.${s.id}`) }),
    icon: s.icon,
    keys: s.goKey ? ["G", s.goKey.toUpperCase()] : undefined,
    run: () => ctx.navigate(s.path),
  }));
  const all: Command[] = [
    ...go,
    { id: "new-item", group: "create", label: t("palette.newItem"), icon: "plus", keys: ["N"], run: () => ctx.navigate("/editor/new") },
    { id: "new-agent", group: "create", label: t("palette.newAgent"), icon: "bot", run: () => ctx.navigate("/agents?new=1") },
    { id: "new-grant", group: "create", label: t("palette.newGrant"), icon: "shield", run: () => ctx.navigate("/policies?new=1") },
    { id: "import-csv", group: "create", label: t("palette.importCsv"), icon: "upload", keywords: "bitwarden 1password keepass chrome firefox", run: () => ctx.navigate("/vault?import=1") },
    { id: "connect", group: "create", label: t("palette.connect"), icon: "terminal", keywords: "mcp claude snippet guide", run: () => ctx.navigate("/dashboard?connect=1") },
    ctx.remote
      ? { id: "lock", group: "vault", label: t("palette.disconnect"), icon: "unplug", keys: ["Ctrl", "L"], keywords: "lock", run: ctx.lock }
      : { id: "lock", group: "vault", label: t("palette.lock"), icon: "lock", keys: ["Ctrl", "L"], run: ctx.lock },
    { id: "panic", group: "vault", label: ctx.remote ? t("remote.collar.panic") : t("palette.panic"), icon: "siren", danger: true, run: ctx.panic },
    { id: "verify", group: "vault", label: t("palette.verify"), icon: "audit", run: ctx.verifyAudit },
    { id: "export-ca", group: "vault", label: t("palette.exportCa"), icon: "download", keywords: "certificate tls", run: ctx.exportCa },
    { id: "backup", group: "vault", label: t("palette.backup"), icon: "download", run: ctx.createBackup },
    { id: "theme", group: "view", label: ctx.themeLabel, icon: "sun", keywords: "dark light appearance", run: ctx.cycleTheme },
    { id: "shortcuts", group: "view", label: t("palette.shortcuts"), icon: "key", keys: ["?"], run: ctx.showShortcuts },
  ];
  return ctx.remote ? all.filter((c) => !LOCAL_ONLY.has(c.id)) : all;
}

export const GROUP_ORDER: readonly CommandGroup[] = ["goto", "create", "vault", "view", "items", "agents"];

/** Case-insensitive match on the label and keywords. Every word of the query must match. */
export function filterCommands<T extends { label: string; keywords?: string }>(items: readonly T[], query: string): T[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [...items];
  return items.filter((item) => {
    const haystack = `${item.label} ${item.keywords ?? ""}`.toLowerCase();
    return words.every((w) => haystack.includes(w));
  });
}
