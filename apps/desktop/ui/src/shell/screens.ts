// The table of screens. This file is shared and fixed: screen tasks do NOT edit it (DEC-T16-1).
// A screen owns only its folder `src/screens/<id>/`.
import type { IconName } from "../ui/Icon";
import { splitQuery } from "./location";

export type ScreenId =
  | "create"
  | "unlock"
  | "dashboard"
  | "vault"
  | "editor"
  | "agents"
  | "policies"
  | "approval"
  | "leases"
  | "audit"
  | "settings";

export interface ScreenDef {
  id: ScreenId;
  /** Route in the `main` window. A screen also owns every path below it (`/vault/...`). */
  path: string;
  /** `app` = rail and top bar (vault open). `solo` = centered, no rail (create, unlock). */
  layout: "app" | "solo";
  icon: IconName;
  /** Shown in the rail. */
  nav: boolean;
  /** Second key of the `G` then key shortcut. */
  goKey?: string;
  /** The rail marks this parent as current while the screen is open. */
  parent?: ScreenId;
}

export const SCREENS: readonly ScreenDef[] = [
  { id: "create", path: "/create", layout: "solo", icon: "plus", nav: false },
  { id: "unlock", path: "/unlock", layout: "solo", icon: "unlock", nav: false },
  { id: "dashboard", path: "/dashboard", layout: "app", icon: "gauge", nav: true, goKey: "d" },
  { id: "vault", path: "/vault", layout: "app", icon: "vault", nav: true, goKey: "v" },
  { id: "editor", path: "/editor", layout: "app", icon: "edit", nav: false, parent: "vault" },
  { id: "agents", path: "/agents", layout: "app", icon: "bot", nav: true, goKey: "a" },
  { id: "policies", path: "/policies", layout: "app", icon: "shield", nav: true, goKey: "p" },
  { id: "approval", path: "/approvals", layout: "app", icon: "bell", nav: true, goKey: "r" },
  { id: "leases", path: "/leases", layout: "app", icon: "timer", nav: true, goKey: "l" },
  { id: "audit", path: "/audit", layout: "app", icon: "audit", nav: true, goKey: "u" },
  { id: "settings", path: "/settings", layout: "app", icon: "sliders", nav: true, goKey: "s" },
];

export const screenById = (id: ScreenId): ScreenDef => {
  const def = SCREENS.find((s) => s.id === id);
  if (!def) throw new Error(`Unknown screen ${id}`);
  return def;
};

/** Finds the screen that owns a location. `/vault/item/3` belongs to `vault`. A `?query` is ignored. */
export function screenForPath(location: string): ScreenDef | null {
  const { path } = splitQuery(location);
  return SCREENS.find((s) => path === s.path || path.startsWith(`${s.path}/`)) ?? null;
}

/** Which rail entry is current for a screen. */
export const navOwner = (def: ScreenDef): ScreenId => def.parent ?? def.id;
