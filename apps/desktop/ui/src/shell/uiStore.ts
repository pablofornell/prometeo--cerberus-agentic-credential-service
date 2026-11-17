import { createStore } from "../state/store";

/** Which global overlay is open. The palette, the shortcut list and the panic dialog are one-at-a-time. */
export type Overlay = "none" | "palette" | "shortcuts" | "panic";

export const overlayStore = createStore<Overlay>("none");
export const openOverlay = (overlay: Overlay) => overlayStore.set(overlay);
export const closeOverlay = () => overlayStore.set("none");
