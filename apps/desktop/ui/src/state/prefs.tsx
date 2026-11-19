// Theme, density, UI scale and language. They are per-person display settings, kept in localStorage (wrapped in
// try/catch: storage can be blocked). They never hold vault data. Settings screen: use `usePrefs()`.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { windowLabel } from "../shell/windowLabel";
import { applyUiScale, sanitizeUiScale, stepUiScale, UI_SCALE_DEFAULT, zoomKeyAction } from "./uiScale";

export type ThemePref = "dark" | "light" | "system";
export type DensityPref = "comfortable" | "compact";
export type LanguagePref = "en";

export interface Prefs {
  theme: ThemePref;
  density: DensityPref;
  /** Whole-window zoom in percent: 80 to 200 in steps of 10 (`uiScale.ts`). */
  uiScale: number;
  language: LanguagePref;
}

export const DEFAULT_PREFS: Prefs = { theme: "dark", density: "comfortable", uiScale: UI_SCALE_DEFAULT, language: "en" };
const STORAGE_KEY = "cerberus-prefs";

export function readPrefs(): Prefs {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Partial<Prefs>;
    return {
      theme: parsed.theme === "light" || parsed.theme === "system" ? parsed.theme : "dark",
      density: parsed.density === "compact" ? "compact" : "comfortable",
      uiScale: sanitizeUiScale(parsed.uiScale),
      language: "en",
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

function write(prefs: Prefs): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // Storage blocked: the choice lasts until the window closes.
  }
}

/**
 * The zoom this window really gets. The approval window is a fixed 440x640 popup: a zoom would clip its buttons, so it
 * stays at 100% whatever the pref is.
 */
export const effectiveUiScale = (prefs: Prefs): number => (windowLabel() === "approval" ? UI_SCALE_DEFAULT : prefs.uiScale);

/**
 * Puts the prefs on `<html>`: no `data-theme` means follow the OS (tokens.css). The approval window is a small popup, so
 * it is always compact, whatever the pref is. It is set on `<html>` and not on the screen, so the toasts (which sit
 * outside the screen) get the compact tokens too.
 */
export function applyPrefs(prefs: Prefs, root: HTMLElement = document.documentElement): void {
  if (prefs.theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", prefs.theme);
  root.setAttribute("data-density", windowLabel() === "approval" ? "compact" : prefs.density);
  root.setAttribute("lang", prefs.language);
  void applyUiScale(effectiveUiScale(prefs), root);
}

interface PrefsApi extends Prefs {
  setTheme: (theme: ThemePref) => void;
  setDensity: (density: DensityPref) => void;
  /** A percent; it is rounded to the step and kept inside 80 to 200. */
  setUiScale: (uiScale: number) => void;
  setLanguage: (language: LanguagePref) => void;
  /** Dark, then light, then follow the OS. */
  cycleTheme: () => void;
  /**
   * The UI scale control registers how to take its pending (not yet applied) scale; returns the way to unregister. A zoom
   * key takes it and steps from it, so the key acts on the scale the user sees and the pending value is always consumed.
   */
  registerPendingScale: (take: () => number | null) => () => void;
}

const PrefsContext = createContext<PrefsApi | null>(null);

export function PrefsProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(readPrefs);
  const takePending = useRef<(() => number | null) | null>(null);

  useEffect(() => {
    applyPrefs(prefs);
    write(prefs);
  }, [prefs]);

  // Ctrl/Cmd + = / + / - / 0 zoom the main window, also inside a text field. Capture phase, so no screen can swallow it.
  useEffect(() => {
    if (windowLabel() === "approval") return;
    const onKeyDown = (e: KeyboardEvent) => {
      const action = zoomKeyAction(e);
      if (!action) return;
      e.preventDefault();
      if (e.repeat) return;
      // The effective scale is the pending one of the UI scale control if it has one, else the stored one. Taking it
      // here (not in the updater, which may run twice) drops it, whatever the key ends up doing.
      const pending = takePending.current?.() ?? null;
      setPrefs((prev) => ({
        ...prev,
        uiScale: action === "reset" ? UI_SCALE_DEFAULT : stepUiScale(pending ?? prev.uiScale, action === "in" ? 1 : -1),
      }));
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, []);

  const registerPendingScale = useCallback((take: () => number | null) => {
    takePending.current = take;
    return () => {
      if (takePending.current === take) takePending.current = null;
    };
  }, []);

  const update = useCallback((patch: Partial<Prefs>) => setPrefs((prev) => ({ ...prev, ...patch })), []);
  const api = useMemo<PrefsApi>(
    () => ({
      ...prefs,
      setTheme: (theme) => update({ theme }),
      setDensity: (density) => update({ density }),
      setUiScale: (uiScale) => update({ uiScale: sanitizeUiScale(uiScale) }),
      setLanguage: (language) => update({ language }),
      cycleTheme: () =>
        setPrefs((prev) => ({
          ...prev,
          theme: prev.theme === "dark" ? "light" : prev.theme === "light" ? "system" : "dark",
        })),
      registerPendingScale,
    }),
    [prefs, update, registerPendingScale],
  );
  return <PrefsContext value={api}>{children}</PrefsContext>;
}

export function usePrefs(): PrefsApi {
  const ctx = useContext(PrefsContext);
  if (!ctx) throw new Error("usePrefs needs a PrefsProvider");
  return ctx;
}
