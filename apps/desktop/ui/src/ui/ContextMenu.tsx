import { useEffect, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { cx } from "./cx";
import { Icon, type IconName } from "./Icon";
import "./context-menu.css";

export interface MenuItemDef {
  id: string;
  label: string;
  icon?: IconName;
  /** A hint at the end of the row, such as "Ctrl+C". It does not bind the key. */
  shortcut?: string;
  /** A destructive action. It still has to go through its confirm dialog. */
  danger?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}

export interface MenuSeparatorDef {
  id: string;
  separator: true;
}

export type MenuEntry = MenuItemDef | MenuSeparatorDef;

const isSeparator = (entry: MenuEntry): entry is MenuSeparatorDef => "separator" in entry;

/** Why the menu closed. The focus goes back to the trigger after a choice, Escape, Tab or another key, not after a click elsewhere. */
export type MenuCloseReason = "select" | "escape" | "tab" | "key" | "outside" | "scroll" | "resize" | "blur";

export interface ContextMenuProps {
  entries: readonly MenuEntry[];
  /** Where the pointer was, in viewport pixels. The menu flips and clamps to stay inside the window. */
  x: number;
  y: number;
  /** The accessible name of the menu. */
  label: string;
  /** Where to draw it. In a modal dialog, pass the dialog: outside of it the menu is out of the focus trap and its clicks close the dialog. Default: `document.body`. */
  container?: HTMLElement | null;
  returnFocusTo?: HTMLElement | null;
  /** Keyboard open: the first item takes the focus. Mouse open: the menu does, and Down picks the first item. */
  focusFirst?: boolean;
  onClose: (reason: MenuCloseReason) => void;
}

const MARGIN = 8;
const MODIFIERS = ["Shift", "Control", "Alt", "Meta", "AltGraph", "CapsLock"];
const RETURNS_FOCUS: readonly MenuCloseReason[] = ["select", "escape", "tab", "key"];

/**
 * An app-native context menu. It sits in a portal at the pointer, flipped and clamped inside the window. Up, Down, Home,
 * End, Enter and Space work, and Escape, Tab, any other key (it still reaches the shortcuts), a click outside, a scroll, a
 * resize or a window blur close it.
 */
export function ContextMenu({ entries, x, y, label, container, returnFocusTo, focusFirst = false, onClose }: ContextMenuProps) {
  const menu = useRef<HTMLDivElement>(null);

  const items = () => Array.from(menu.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not([aria-disabled="true"])') ?? []);

  const close = (reason: MenuCloseReason) => {
    if (RETURNS_FOCUS.includes(reason)) returnFocusTo?.focus({ preventScroll: true });
    onClose(reason);
  };

  const choose = (entry: MenuEntry) => {
    if (isSeparator(entry) || entry.disabled) return;
    close("select");
    entry.onSelect();
  };

  // Place it before the first paint. A dialog moves the origin of `position: fixed` (it has a transform), so read the
  // real origin of the menu first and subtract it.
  useLayoutEffect(() => {
    const el = menu.current;
    if (!el) return;
    el.style.left = "0px";
    el.style.top = "0px";
    const origin = el.getBoundingClientRect();
    const width = el.offsetWidth;
    const height = el.offsetHeight;
    // The room is the window, or the dialog the menu sits in: a dialog clips what sticks out of it.
    const room = container?.getBoundingClientRect() ?? { left: 0, top: 0, right: document.documentElement.clientWidth, bottom: document.documentElement.clientHeight };
    const place = (at: number, size: number, from: number, to: number) => {
      const flipped = at + size + MARGIN > to ? at - size : at;
      return Math.max(from + MARGIN, Math.min(flipped, to - size - MARGIN));
    };
    el.style.left = `${place(x, width, room.left, room.right) - origin.left}px`;
    el.style.top = `${place(y, height, room.top, room.bottom) - origin.top}px`;
    el.dataset.ready = "";
  }, [x, y, entries, container]);

  useEffect(() => {
    const first = focusFirst ? items()[0] : undefined;
    (first ?? menu.current)?.focus({ preventScroll: true });
    // Once per open: the provider gives each open a new key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const el = menu.current;
    if (!el) return;
    const move = (to: "next" | "prev" | "first" | "last") => {
      const list = items();
      if (list.length === 0) return;
      const at = list.indexOf(document.activeElement as HTMLButtonElement);
      const index =
        to === "first" ? 0 : to === "last" ? list.length - 1 : to === "next" ? (at < 0 ? 0 : (at + 1) % list.length) : at < 0 ? list.length - 1 : (at - 1 + list.length) % list.length;
      list[index]?.focus({ preventScroll: true });
    };
    // The window sees the key before a dialog under the menu does, so Escape closes the menu and not the dialog.
    const onKey = (event: KeyboardEvent) => {
      // A bare modifier is the start of a chord, not a key press.
      if (MODIFIERS.includes(event.key)) return;
      // A shortcut (Ctrl+L, Ctrl+K) must not leave the menu behind. The event goes on: it is not ours.
      if (event.ctrlKey || event.metaKey || event.altKey) {
        close("key");
        return;
      }
      const own = (): void => {
        event.preventDefault();
        event.stopPropagation();
      };
      switch (event.key) {
        case "Escape":
          own();
          close("escape");
          break;
        case "Tab":
          own();
          close("tab");
          break;
        case "ArrowDown":
          own();
          move("next");
          break;
        case "ArrowUp":
          own();
          move("prev");
          break;
        case "Home":
          own();
          move("first");
          break;
        case "End":
          own();
          move("last");
          break;
        case "Enter":
        case " ": {
          own();
          const index = items().indexOf(document.activeElement as HTMLButtonElement);
          const target = items()[index];
          const entry = entries.find((e) => !isSeparator(e) && target?.dataset.id === e.id);
          if (entry) choose(entry);
          break;
        }
        default:
          // Any other key (`n`, `g`, `/`) closes the menu and goes on to the shortcuts.
          close("key");
      }
    };
    const onPointerDown = (event: PointerEvent) => {
      if (!el.contains(event.target as Node)) close("outside");
    };
    const onScroll = (event: Event) => {
      if (!el.contains(event.target as Node)) close("scroll");
    };
    const onResize = () => close("resize");
    const onBlur = () => close("blur");
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("pointerdown", onPointerDown, true);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onResize);
    window.addEventListener("blur", onBlur);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("pointerdown", onPointerDown, true);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("blur", onBlur);
    };
    // The handlers read the current props through the closure of each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entries, onClose, returnFocusTo]);

  return createPortal(
    <div ref={menu} className="ctx-menu" role="menu" aria-label={label} tabIndex={-1} onContextMenu={(e) => e.preventDefault()}>
      {entries.map((entry) =>
        isSeparator(entry) ? (
          <div key={entry.id} className="ctx-sep" role="separator" />
        ) : (
          <button
            key={entry.id}
            type="button"
            role="menuitem"
            tabIndex={-1}
            data-id={entry.id}
            className={cx("ctx-item", entry.danger && "danger")}
            aria-disabled={entry.disabled || undefined}
            // Keep the focus and the text selection where they are until the choice is made.
            onMouseDown={(e) => e.preventDefault()}
            onMouseMove={(e) => {
              if (!entry.disabled && document.activeElement !== e.currentTarget) e.currentTarget.focus({ preventScroll: true });
            }}
            onClick={() => choose(entry)}
          >
            {entry.icon ? <Icon name={entry.icon} /> : <span className="ctx-gap" aria-hidden="true" />}
            <span className="ctx-label">{entry.label}</span>
            {entry.shortcut && <span className="ctx-key">{entry.shortcut}</span>}
          </button>
        ),
      )}
    </div>,
    container ?? document.body,
  );
}
