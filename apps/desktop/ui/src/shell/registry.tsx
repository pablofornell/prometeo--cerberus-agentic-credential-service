// Loads each `src/screens/<id>/route.tsx` by its fixed name. Adding or replacing a screen needs no edit here.
import { createElement, type ComponentType } from "react";
import { SCREENS, type ScreenId } from "./screens";

type ScreenModule = { default: ComponentType };

const modules = import.meta.glob<ScreenModule>("../screens/*/route.tsx", { eager: true });

const byId = new Map<string, ComponentType>();
for (const [file, mod] of Object.entries(modules)) {
  const id = /\/screens\/([^/]+)\/route\.tsx$/.exec(file)?.[1];
  if (id) byId.set(id, mod.default);
}

for (const screen of SCREENS) {
  if (!byId.has(screen.id)) {
    throw new Error(`Screen folder missing: src/screens/${screen.id}/route.tsx must export a default component`);
  }
}

/** Renders the screen of a folder. Screens are looked up by id, never imported by name elsewhere. */
export function ScreenView({ id }: { id: ScreenId }) {
  const component = byId.get(id);
  if (!component) throw new Error(`Screen folder missing: ${id}`);
  return createElement(component);
}
