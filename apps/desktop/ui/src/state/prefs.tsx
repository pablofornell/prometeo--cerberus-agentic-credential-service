// Theme, density and language. They are per-person display settings, kept in localStorage (wrapped in
// try/catch: storage can be blocked). They never hold vault data. Settings screen: use `usePrefs()`.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type ThemePref = "dark" | "light" | "system";
export type DensityPref = "comfortable" | "compact";
export type LanguagePref = "en";

export interface Prefs {
  theme: ThemePref;
  density: DensityPref;
  language: LanguagePref;
}

export const DEFAULT_PREFS: Prefs = { theme: "dark", density: "comfortable", language: "en" };
const STORAGE_KEY = "cerberus-prefs";

function read(): Prefs {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Partial<Prefs>;
    return {
      theme: parsed.theme === "light" || parsed.theme === "system" ? parsed.theme : "dark",
      density: parsed.density === "compact" ? "compact" : "comfortable",
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

/** Puts the prefs on `<html>`: no `data-theme` means follow the OS (tokens.css). */
export function applyPrefs(prefs: Prefs, root: HTMLElement = document.documentElement): void {
  if (prefs.theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", prefs.theme);
  root.setAttribute("data-density", prefs.density);
  root.setAttribute("lang", prefs.language);
}

interface PrefsApi extends Prefs {
  setTheme: (theme: ThemePref) => void;
  setDensity: (density: DensityPref) => void;
  setLanguage: (language: LanguagePref) => void;
  /** Dark, then light, then follow the OS. */
  cycleTheme: () => void;
}

const PrefsContext = createContext<PrefsApi | null>(null);

export function PrefsProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(read);

  useEffect(() => {
    applyPrefs(prefs);
    write(prefs);
  }, [prefs]);

  const update = useCallback((patch: Partial<Prefs>) => setPrefs((prev) => ({ ...prev, ...patch })), []);
  const api = useMemo<PrefsApi>(
    () => ({
      ...prefs,
      setTheme: (theme) => update({ theme }),
      setDensity: (density) => update({ density }),
      setLanguage: (language) => update({ language }),
      cycleTheme: () =>
        setPrefs((prev) => ({
          ...prev,
          theme: prev.theme === "dark" ? "light" : prev.theme === "light" ? "system" : "dark",
        })),
    }),
    [prefs, update],
  );
  return <PrefsContext value={api}>{children}</PrefsContext>;
}

export function usePrefs(): PrefsApi {
  const ctx = useContext(PrefsContext);
  if (!ctx) throw new Error("usePrefs needs a PrefsProvider");
  return ctx;
}
