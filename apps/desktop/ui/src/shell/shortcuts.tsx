import { useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { t } from "../i18n";
import { modLabel } from "../state/uiScale";
import { Dialog, Kbd } from "../ui";
import { useShellActions } from "./actions";
import { SCREENS } from "./screens";
import { closeOverlay, openOverlay, overlayStore } from "./uiStore";

const GO_WINDOW_MS = 1500;

const isEditable = (el: EventTarget | null): boolean =>
  el instanceof HTMLElement && (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));

/**
 * Keyboard map (IA section 5). Ctrl/Cmd+K and Ctrl/Cmd+L work everywhere in the main window. Single keys
 * (`G` then a letter, `N`, `/`, `?`) do nothing while focus is in a field or a dialog is open.
 * No key approves or revokes anything. The zoom keys (Ctrl/Cmd with `=` `+` `-` `0`) are not here: they work on every
 * screen of the main window, also the unlock screen, so `PrefsProvider` handles them.
 */
export function useGlobalShortcuts(): void {
  const actions = useShellActions();
  const [, navigate] = useLocation();
  const latest = useRef({ actions, navigate });
  useEffect(() => {
    latest.current = { actions, navigate };
  });

  useEffect(() => {
    let goPending = false;
    let goTimer: ReturnType<typeof setTimeout> | undefined;
    const clearGo = () => {
      goPending = false;
      if (goTimer) clearTimeout(goTimer);
    };

    const onKeyDown = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (mod && !e.altKey && !e.shiftKey && key === "k") {
        e.preventDefault();
        if (overlayStore.get() === "palette") closeOverlay();
        else openOverlay("palette");
        return;
      }
      if (mod && !e.altKey && !e.shiftKey && key === "l") {
        e.preventDefault();
        latest.current.actions.lock();
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey || isEditable(e.target)) return;
      if (overlayStore.get() !== "none" || document.querySelector('[role="dialog"]')) return;

      if (goPending) {
        clearGo();
        const target = SCREENS.find((s) => s.goKey === key);
        if (target) {
          e.preventDefault();
          latest.current.navigate(target.path);
        }
        return;
      }
      if (key === "g") {
        goPending = true;
        goTimer = setTimeout(clearGo, GO_WINDOW_MS);
      } else if (e.key === "?") {
        e.preventDefault();
        openOverlay("shortcuts");
      } else if (key === "n") {
        e.preventDefault();
        latest.current.navigate("/editor/new");
      } else if (key === "/") {
        const search = document.querySelector<HTMLElement>("[data-search]");
        if (search) {
          e.preventDefault();
          search.focus();
        }
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      clearGo();
    };
  }, []);
}

const ROWS: readonly { label: Parameters<typeof t>[0]; keys: readonly string[] }[] = [
  { label: "shortcuts.palette", keys: ["Ctrl", "K"] },
  { label: "shortcuts.lock", keys: ["Ctrl", "L"] },
  { label: "shortcuts.goto", keys: ["G", "D V A P R L U S"] },
  { label: "shortcuts.new", keys: ["N"] },
  { label: "shortcuts.search", keys: ["/"] },
  { label: "shortcuts.help", keys: ["?"] },
  { label: "shortcuts.close", keys: ["Esc"] },
  { label: "shortcuts.hold", keys: ["Space"] },
  { label: "shortcuts.zoomIn", keys: ["Ctrl", "+"] },
  { label: "shortcuts.zoomOut", keys: ["Ctrl", "-"] },
  { label: "shortcuts.zoomReset", keys: ["Ctrl", "0"] },
];

export function ShortcutsDialog() {
  const open = overlayStore.use() === "shortcuts";
  return (
    <Dialog open={open} onOpenChange={(next) => !next && closeOverlay()} title={t("shortcuts.title")}>
      <dl className="kv">
        {ROWS.map((row) => (
          <div key={row.label} className="kv-row">
            <dt>{t(row.label)}</dt>
            <dd>
              {row.keys.map((k) => (
                <Kbd key={k}>{k === "Ctrl" ? modLabel() : k}</Kbd>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </Dialog>
  );
}
