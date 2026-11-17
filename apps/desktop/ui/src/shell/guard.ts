import type { VaultState } from "../bindings";
import type { ScreenDef } from "./screens";

/** The route a state sends you to when the current one is not allowed (IA section 1). */
export const DEFAULT_ROUTE: Record<Exclude<VaultState, "locking">, string> = {
  no_vault: "/create",
  sealed: "/unlock",
  unlocked: "/dashboard",
};

/**
 * Router guard for the `main` window. Returns the path to go to, or `null` when the location is fine.
 * `locking` never redirects: the shell shows the locked state until the vault is sealed.
 * While `creating` is true, an unlocked vault keeps the `create` screen (the recovery key is not saved yet).
 * While `stranded` is true (a failed restore left the vault as an old file), there is no vault but the create
 * screen is closed: only the unlock screen, which offers to put the old vault back, is allowed (T27-G).
 */
export function resolveRoute(state: VaultState, screen: ScreenDef | null, creating = false, stranded = false): string | null {
  if (state === "locking") return null;
  const fallback = state === "no_vault" && stranded ? "/unlock" : DEFAULT_ROUTE[state];
  if (!screen) return fallback;
  switch (state) {
    case "no_vault":
      if (stranded) return screen.id === "unlock" ? null : fallback;
      return screen.id === "create" || screen.id === "unlock" ? null : fallback;
    case "sealed":
      return screen.id === "unlock" ? null : fallback;
    case "unlocked":
      if (creating && screen.id === "create") return null;
      return screen.layout === "app" ? null : fallback;
  }
}
