import type { MessageKeyOf } from "./types";

/** The item fields a column can feed, in the order of the mapping step. The names match the backend. */
export const FIELDS = [
  "title",
  "kind",
  "url",
  "username",
  "password",
  "secret",
  "totp",
  "notes",
  "tags",
  "description",
  "role",
  "category",
  "environment",
] as const;
export type CsvField = (typeof FIELDS)[number];

export const fieldMessage = (field: CsvField): MessageKeyOf => `imp.f.${field}`;

const ALIASES: Record<CsvField, readonly string[]> = {
  title: ["title", "name", "label"],
  kind: ["kind", "type"],
  url: ["url", "uri", "website", "login_uri", "target"],
  username: ["username", "user", "login", "user name"],
  password: ["password", "pass"],
  secret: ["secret", "value", "key", "token"],
  totp: ["totp", "otp", "otpauth"],
  notes: ["notes", "note", "comments"],
  tags: ["tags", "folder", "group"],
  description: ["description"],
  role: ["role", "role_label"],
  category: ["category"],
  environment: ["environment", "env"],
};

/** A first guess of the mapping from the header names. The person can change every choice. */
export function guessMapping(columns: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of FIELDS) {
    const hit = columns.find((c) => ALIASES[field].includes(c.trim().toLowerCase()));
    if (hit !== undefined) out[field] = hit;
  }
  return out;
}

/** Today's file name for the export: `cerberus-export-2026-11-17.csv`. */
export const exportName = (now = new Date()): string => `cerberus-export-${now.toISOString().slice(0, 10)}.csv`;
