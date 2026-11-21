import { createContext, useCallback, useContext, useMemo, useRef, useEffect, useState, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";
import { useLocation } from "wouter";
import { t } from "../i18n";
import { vaultStateStore } from "../state/live";
import { ContextMenu, type MenuEntry } from "./ContextMenu";
import { editableOf, textMenu } from "./editMenu";

interface OpenMenu {
  key: number;
  entries: readonly MenuEntry[];
  x: number;
  y: number;
  label: string;
  trigger: HTMLElement | null;
  container: HTMLElement | null;
  focusFirst: boolean;
}

export interface TargetProps {
  onContextMenu: (event: MouseEvent<HTMLElement>) => void;
  onKeyDown: (event: KeyboardEvent<HTMLElement>) => void;
}

interface ContextMenuApi {
  /**
   * Handlers that make an element a context menu target: right click, the Menu key and Shift+F10. `build` runs when the
   * menu opens. It returns the entries, or null for no menu. A target inside an editable field is left to the text menu.
   */
  targetProps: (build: () => readonly MenuEntry[] | null, label?: string) => TargetProps;
}

const NONE: ContextMenuApi = { targetProps: () => ({ onContextMenu: () => undefined, onKeyDown: () => undefined }) };

const ContextMenuContext = createContext<ContextMenuApi>(NONE);

/** The context menu API for a screen. Outside of a provider (a bare component test) no target opens a menu. */
export const useContextMenu = (): ContextMenuApi => useContext(ContextMenuContext);

/** Shift+right click reaches the webview's own menu (Inspect) in a dev build only. */
const nativePass = (event: { shiftKey: boolean }): boolean => import.meta.env.DEV && event.shiftKey;

const isMenuKey = (event: { key: string; shiftKey: boolean }): boolean => event.key === "ContextMenu" || (event.shiftKey && event.key === "F10");

/** The `contextmenu` event of a key press follows its `keydown` at once. */
const KEY_TO_MENU_MS = 500;

/**
 * Where the last input came from. The webview does not say whether `contextmenu` came from a key or the mouse: WebKit
 * gives a key-opened event the position of the focused element, not (0, 0). So the provider watches the keydown of the
 * Menu key and Shift+F10, and the pointer buttons, and reads that when `contextmenu` arrives.
 */
interface LastInput {
  menuKeyAt: number | null;
}

/** Where a keyboard open puts the menu: on the focused element. */
function anchorOf(el: Element): { x: number; y: number } {
  const rect = el.getBoundingClientRect();
  return { x: rect.left + Math.min(24, rect.width / 2), y: rect.top + rect.height / 2 };
}

const dialogOf = (el: Element | null): HTMLElement | null => el?.closest<HTMLElement>('[role="dialog"], [role="alertdialog"]') ?? null;

const focusable = (el: EventTarget | null): HTMLElement | null => (el instanceof HTMLElement && el !== document.body ? el : null);

/**
 * The one place that owns the right click. It hides the webview's menu (Back, Reload, Inspect) everywhere. Targets that
 * ask for it get their own menu. An editable field, or a selection in plain text, gets the text menu. Anywhere else
 * there is no menu at all.
 */
export function ContextMenuProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState<OpenMenu | null>(null);
  const counter = useRef(0);
  const last = useRef<LastInput>({ menuKeyAt: null });
  const [location] = useLocation();
  const vaultState = vaultStateStore.use();

  /** True when this `contextmenu` event is the one a Menu key or Shift+F10 press asked for. */
  const fromKeyboard = useCallback((): boolean => {
    const at = last.current.menuKeyAt;
    return at !== null && performance.now() - at < KEY_TO_MENU_MS;
  }, []);

  // A menu belongs to the screen and the unlocked vault it opened on. Leaving either closes it.
  // Adjusted during render, not in an effect: the stale menu never paints.
  const scope = `${location}\n${vaultState}`;
  const [seen, setSeen] = useState(scope);
  if (seen !== scope) {
    setSeen(scope);
    setOpen(null);
  }

  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      last.current.menuKeyAt = isMenuKey(event) ? performance.now() : null;
    };
    const onPointerDown = () => {
      last.current.menuKeyAt = null;
    };
    window.addEventListener("keydown", onKeyDown, true);
    window.addEventListener("pointerdown", onPointerDown, true);
    return () => {
      window.removeEventListener("keydown", onKeyDown, true);
      window.removeEventListener("pointerdown", onPointerDown, true);
    };
  }, []);

  const show = useCallback((menu: Omit<OpenMenu, "key">) => {
    counter.current += 1;
    setOpen({ ...menu, key: counter.current });
  }, []);

  const targetProps = useCallback<ContextMenuApi["targetProps"]>(
    (build, label = t("menu.actions")) => ({
      onContextMenu: (event) => {
        if (event.defaultPrevented || editableOf(event.target) !== null) return;
        const keyboard = fromKeyboard();
        if (!keyboard && nativePass(event)) return;
        const entries = build();
        if (!entries || entries.length === 0) return;
        event.preventDefault();
        const at = keyboard ? anchorOf(event.currentTarget) : { x: event.clientX, y: event.clientY };
        show({ entries, ...at, label, trigger: focusable(document.activeElement) ?? event.currentTarget, container: dialogOf(event.currentTarget), focusFirst: keyboard });
      },
      onKeyDown: (event) => {
        if (event.defaultPrevented || !isMenuKey(event) || editableOf(event.target) !== null) return;
        const entries = build();
        if (!entries || entries.length === 0) return;
        event.preventDefault();
        const source = event.target as HTMLElement;
        show({ entries, ...anchorOf(source), label, trigger: source, container: dialogOf(source), focusFirst: true });
      },
    }),
    [show, fromKeyboard],
  );

  // Everything the targets did not take. React handles the event at the root first, so `defaultPrevented` tells.
  useEffect(() => {
    const onContextMenu = (event: globalThis.MouseEvent) => {
      if (event.defaultPrevented) return;
      const keyboard = fromKeyboard();
      if (!keyboard && nativePass(event)) return;
      event.preventDefault();
      const field = editableOf(event.target);
      const entries = textMenu(field);
      if (!entries) return;
      const target = event.target as Element;
      const at = keyboard ? anchorOf(field ?? target) : { x: event.clientX, y: event.clientY };
      show({ entries, ...at, label: t("menu.text"), trigger: field ?? focusable(document.activeElement), container: dialogOf(target), focusFirst: keyboard });
    };
    document.addEventListener("contextmenu", onContextMenu);
    return () => document.removeEventListener("contextmenu", onContextMenu);
  }, [show, fromKeyboard]);

  const api = useMemo<ContextMenuApi>(() => ({ targetProps }), [targetProps]);

  return (
    <ContextMenuContext.Provider value={api}>
      {children}
      {open && (
        <ContextMenu
          key={open.key}
          entries={open.entries}
          x={open.x}
          y={open.y}
          label={open.label}
          container={open.container}
          returnFocusTo={open.trigger}
          focusFirst={open.focusFirst}
          onClose={() => setOpen(null)}
        />
      )}
    </ContextMenuContext.Provider>
  );
}
