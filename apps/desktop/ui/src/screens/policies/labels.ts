import type { DayOfWeek, Environment, GrantMode, ItemKind, Permission } from "../../bindings";

export const PERMISSIONS: readonly Permission[] = ["read", "find", "create_session", "write", "use_ssh"];
export const ENVIRONMENTS: readonly Environment[] = ["dev", "staging", "prod", "other"];
export const MODES: readonly GrantMode[] = ["auto", "ask_once", "ask_always", "deny"];
export const KINDS: readonly ItemKind[] = [
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
  "rustdesk",
];
export const DAYS: readonly DayOfWeek[] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
/** Built-in categories (PLAN section 3). The person may add more; a grant matches the text. */
export const CATEGORIES: readonly string[] = ["Web login", "API key", "SSH", "Session", "Database", "Cloud", "Certificate", "Remote desktop", "Other"];
export const ROLE_LABELS: readonly string[] = ["admin", "normal user", "read-only", "SAI user"];
