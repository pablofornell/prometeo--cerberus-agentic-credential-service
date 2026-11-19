// UI scale: zooms the whole window. Pure maths and key matching, plus the one function that applies the zoom.
// The value is a percent, kept in the prefs (`prefs.tsx`) next to theme and density.
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { windowLabel } from "../shell/windowLabel";

export const UI_SCALE_MIN = 80;
export const UI_SCALE_MAX = 200;
export const UI_SCALE_STEP = 10;
export const UI_SCALE_DEFAULT = 100;

/** A percent on the step grid inside the limits. Anything that is not a finite number becomes 100. */
export function sanitizeUiScale(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return UI_SCALE_DEFAULT;
  const stepped = Math.round(value / UI_SCALE_STEP) * UI_SCALE_STEP;
  return Math.min(UI_SCALE_MAX, Math.max(UI_SCALE_MIN, stepped));
}

/** One step up or down, kept inside the limits. */
export const stepUiScale = (current: number, dir: 1 | -1): number => sanitizeUiScale(current + dir * UI_SCALE_STEP);

export type ZoomAction = "in" | "out" | "reset";

type ZoomKeyEvent = Pick<KeyboardEvent, "key" | "code" | "ctrlKey" | "metaKey" | "altKey">;

const isMac = (): boolean => typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

/** "Cmd" on macOS, "Ctrl" elsewhere: the modifier of the zoom keys, for the labels. */
export const modLabel = (): string => (isMac() ? "Cmd" : "Ctrl");

/**
 * The zoom action of a keydown, or null. Ctrl (Cmd on macOS) with `=` or `+` zooms in, `-` zooms out, `0` resets.
 * The keys are matched by the character they type, not by the physical key: `+` and `-` are not where a US keyboard has
 * them on many layouts. Shift is ignored (`+` needs it on a US layout), the numpad keys type the same characters (with
 * NumLock off numpad 0 is `Insert`, so Ctrl+Insert stays a copy), and Alt is refused so AltGr combinations (Ctrl+Alt on
 * Windows) still type their character.
 */
export function zoomKeyAction(e: ZoomKeyEvent, mac: boolean = isMac()): ZoomAction | null {
  const mod = mac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
  if (!mod || e.altKey) return null;
  if (e.key === "=" || e.key === "+") return "in";
  if (e.key === "-") return "out";
  if (e.key === "0") return "reset";
  return null;
}

/**
 * True in the desktop app, false in a plain browser. It asks for `window.isTauri`, which only the real runtime sets: the
 * dev mock (`mockIPC`) fakes `__TAURI_INTERNALS__` but not this, and it has no webview to zoom.
 */
export const inTauri = (): boolean => isTauri();

/** The zoom the webview confirmed. null: none yet (or the last try failed), so the next call sends one (a reload keeps the old zoom). */
let lastZoom: number | null = null;
/** The zoom the app wants now. The sender keeps going until the webview has this one. */
let wantedZoom: number | null = null;
/** The running sender, null when idle. Only one `setZoom` is in flight, so the calls cannot land out of order. */
let sender: Promise<void> | null = null;
/** How long the start waits for the webview to confirm the zoom before it shows the screen anyway. */
const EARLY_WAIT_MS = 400;

/**
 * The browser zoom: the CSS `zoom` of `<html>`. `--ui-zoom` and `data-css-zoom` let `extras.css` give back what the
 * viewport units gain from it. At 100% all three are removed.
 */
function setCssZoom(root: HTMLElement, scale: number): void {
  if (scale === UI_SCALE_DEFAULT) {
    root.style.removeProperty("zoom");
    root.style.removeProperty("--ui-zoom");
    root.removeAttribute("data-css-zoom");
    return;
  }
  root.style.setProperty("zoom", String(scale / 100));
  root.style.setProperty("--ui-zoom", String(scale / 100));
  root.setAttribute("data-css-zoom", "");
}

/** Sends the wanted zoom, one call at a time; when a call settles it sends only the newest wish, and only if it differs. */
async function sendZoom(): Promise<void> {
  while (wantedZoom !== null && wantedZoom !== lastZoom) {
    const next = wantedZoom;
    try {
      await getCurrentWebview().setZoom(next / 100);
      lastZoom = next;
    } catch {
      lastZoom = null;
      if (wantedZoom === next) return;
    }
  }
}

/**
 * Zooms the window to `percent`. In the desktop app that is the webview zoom: a true page zoom, CSS px and `vh` stay
 * consistent. In a plain browser (dev server, LAN) there is no webview, so it is the CSS `zoom` of `<html>`. The
 * approval window never zooms (its ACL refuses it, and it is a fixed popup).
 * Resolves when the webview has the zoom; a failure is not an error (the window stays as it is).
 */
export async function applyUiScale(percent: number, root: HTMLElement = document.documentElement): Promise<void> {
  if (windowLabel() === "approval") return;
  const scale = sanitizeUiScale(percent);
  if (!inTauri()) {
    setCssZoom(root, scale);
    return;
  }
  setCssZoom(root, UI_SCALE_DEFAULT);
  wantedZoom = scale;
  sender ??= sendZoom().finally(() => {
    sender = null;
  });
  await sender;
}

/** At start: waits for the webview zoom (at most `EARLY_WAIT_MS`), so the first screen is drawn at its final size. */
export async function applyUiScaleEarly(percent: number): Promise<void> {
  if (windowLabel() === "approval") return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, EARLY_WAIT_MS);
  });
  try {
    await Promise.race([applyUiScale(percent), timeout]);
  } finally {
    clearTimeout(timer);
  }
}
