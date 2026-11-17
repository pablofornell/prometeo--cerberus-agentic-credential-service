// Pure filter and count logic of the vault browser. Items arrive as metadata only (no secrets).
import type { Environment, ItemKind, ItemSummaryView_Serialize as Item } from "../../bindings";
import { BUILTIN_CATEGORIES } from "./kinds";

export interface Filters {
  /** Workspace slug. */
  workspace: string | null;
  category: string | null;
  tag: string | null;
  kind: ItemKind | "";
  env: Environment | "";
  role: string;
  /** Free text. The backend index answers it, see `matchIds`. */
  q: string;
}

export const NO_FILTERS: Filters = { workspace: null, category: null, tag: null, kind: "", env: "", role: "", q: "" };

export const hasActiveFilters = (f: Filters): boolean =>
  f.workspace !== null || f.category !== null || f.tag !== null || f.kind !== "" || f.env !== "" || f.role !== "" || f.q.trim() !== "";

/** `matchIds` is the answer of the backend search for `f.q`. `null` means no search is active. */
export function applyFilters(items: readonly Item[], f: Filters, matchIds: ReadonlySet<string> | null): Item[] {
  return items.filter(
    (item) =>
      (f.workspace === null || item.workspace === f.workspace) &&
      (f.category === null || item.category === f.category) &&
      (f.tag === null || item.tags.includes(f.tag)) &&
      (f.kind === "" || item.kind === f.kind) &&
      (f.env === "" || item.environment === f.env) &&
      (f.role === "" || item.role_label === f.role) &&
      (matchIds === null || matchIds.has(item.id)),
  );
}

export interface Facet {
  name: string;
  count: number;
}

const countBy = (values: readonly string[]): Map<string, number> => {
  const map = new Map<string, number>();
  for (const v of values) map.set(v, (map.get(v) ?? 0) + 1);
  return map;
};

/** Built-in categories first (always shown), then custom ones by name. */
export function categoryFacets(items: readonly Item[]): Facet[] {
  const counts = countBy(items.map((i) => i.category));
  const builtin = BUILTIN_CATEGORIES.map((name) => ({ name, count: counts.get(name) ?? 0 }));
  const custom = [...counts.entries()]
    .filter(([name]) => !(BUILTIN_CATEGORIES as readonly string[]).includes(name))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, count]) => ({ name, count }));
  return [...builtin, ...custom];
}

/** Tags by use, then by name. */
export function tagFacets(items: readonly Item[]): Facet[] {
  const counts = countBy(items.flatMap((i) => i.tags));
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

/** Role labels of the items, presets first. */
export function roleOptions(items: readonly Item[], presets: readonly string[]): string[] {
  const seen = new Set(items.flatMap((i) => (i.role_label ? [i.role_label] : [])));
  const custom = [...seen].filter((r) => !presets.includes(r)).sort((a, b) => a.localeCompare(b));
  return [...presets, ...custom];
}

export const workspaceCounts = (items: readonly Item[]): Map<string, number> => countBy(items.map((i) => i.workspace));

/** Total seconds of a session item's life, taken from its last change to its end. `null` for items that do not expire. */
export function ttlSpan(item: Item): { total: number; endsAt: number } | null {
  if (!item.expires_at) return null;
  const end = Date.parse(item.expires_at);
  const start = Date.parse(item.updated_at);
  if (Number.isNaN(end)) return null;
  const total = Number.isNaN(start) ? 3600 : Math.max(60, Math.round((end - start) / 1000));
  return { total, endsAt: end };
}
