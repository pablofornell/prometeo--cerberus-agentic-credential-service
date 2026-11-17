// Facts about item kinds and categories. The vault screen and the editor screen both read them.
import type { Environment, ItemKind } from "../../bindings";
import { defineMessages } from "../../i18n";
import type { IconName } from "../../ui";

export const KIND_ORDER: readonly ItemKind[] = [
  "web_login",
  "api_key",
  "ssh_key",
  "session_token",
  "browser_session",
  "database",
  "cloud",
  "certificate",
  "env_bundle",
  "note",
];

export const kindMessages = defineMessages({
  "kind.web_login": "Web login",
  "kind.api_key": "API key",
  "kind.ssh_key": "SSH key",
  "kind.session_token": "Session token",
  "kind.browser_session": "Browser session",
  "kind.database": "Database",
  "kind.cloud": "Cloud",
  "kind.certificate": "Certificate",
  "kind.env_bundle": "Env bundle",
  "kind.note": "Note",
});

export const kindLabel = (kind: ItemKind): string => kindMessages[`kind.${kind}`];

export const ENVIRONMENTS: readonly Environment[] = ["dev", "staging", "prod", "other"];

/** The built-in categories (PLAN section 3). The person can add more by typing a new name. */
export const BUILTIN_CATEGORIES = ["Web login", "API key", "SSH", "Session", "Database", "Cloud", "Certificate", "Other"] as const;

export const CATEGORY_ICON: Record<string, IconName> = {
  "Web login": "globe",
  "API key": "key",
  SSH: "terminal",
  Session: "ticket",
  Database: "database",
  Cloud: "cloud",
  Certificate: "cert",
  Other: "note",
};

export const categoryIcon = (category: string): IconName => CATEGORY_ICON[category] ?? "note";

/** The category an item of this kind gets by default. */
export const DEFAULT_CATEGORY: Record<ItemKind, (typeof BUILTIN_CATEGORIES)[number]> = {
  web_login: "Web login",
  api_key: "API key",
  ssh_key: "SSH",
  session_token: "Session",
  browser_session: "Session",
  database: "Database",
  cloud: "Cloud",
  certificate: "Certificate",
  env_bundle: "Other",
  note: "Other",
};

export const isSessionKind = (kind: ItemKind): boolean => kind === "session_token" || kind === "browser_session";

export const isItemKind = (value: string): value is ItemKind => (KIND_ORDER as readonly string[]).includes(value);

/** Preset role labels (the chips of the editor and the role filter). */
export { ROLE_PRESETS } from "../../ui";

/** Date and time for a person, in the local format. */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
