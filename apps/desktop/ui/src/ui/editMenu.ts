// The text menu: Cut, Copy, Paste and Select all for an editable field, Copy for a selection in plain text.
import { t } from "../i18n";
import { modLabel } from "../state/uiScale";
import type { MenuEntry } from "./ContextMenu";

/** Input types that hold text a person types. A checkbox, a range or a button has none. */
const TEXT_TYPES = new Set(["", "text", "search", "email", "url", "tel", "password", "number"]);

type Field = HTMLInputElement | HTMLTextAreaElement;

const isField = (el: Element | null): el is Field => el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;

/** The editable element the target is in (an input, a textarea or a contenteditable), or null. */
export function editableOf(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof Element)) return null;
  const field = target.closest("input, textarea");
  if (field instanceof HTMLTextAreaElement) return field;
  if (field instanceof HTMLInputElement) return TEXT_TYPES.has(field.type) ? field : null;
  return target.closest<HTMLElement>('[contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"]');
}

function selectedText(editable: HTMLElement | null): string {
  if (isField(editable)) {
    const { selectionStart: from, selectionEnd: to } = editable;
    return from !== null && to !== null ? editable.value.slice(from, to) : "";
  }
  return window.getSelection()?.toString() ?? "";
}

const exec = (command: string, value?: string): boolean => typeof document.execCommand === "function" && document.execCommand(command, false, value);

/** Copy goes through `execCommand` in a field (it keeps the field's own selection) and through the clipboard API elsewhere. */
function copy(text: string, viaCommand: boolean): void {
  if (viaCommand && exec("copy")) return;
  const fallback = () => void exec("copy");
  if (navigator.clipboard === undefined) fallback();
  else navigator.clipboard.writeText(text).catch(fallback);
}

function insert(editable: HTMLElement, text: string): void {
  if (exec("insertText", text)) return;
  if (isField(editable)) {
    editable.setRangeText(text, editable.selectionStart ?? editable.value.length, editable.selectionEnd ?? editable.value.length, "end");
    editable.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

async function paste(editable: HTMLElement): Promise<void> {
  try {
    insert(editable, await navigator.clipboard.readText());
  } catch {
    // The webview refused the read. Fall back to the paste command, which may refuse too: Ctrl+V still works.
    exec("paste");
  }
}

/** The entries for a right click on `editable`, or on plain text. Null when there is nothing to offer. */
export function textMenu(editable: HTMLElement | null): MenuEntry[] | null {
  const text = selectedText(editable);
  const mod = modLabel();
  if (editable === null) {
    return text === "" ? null : [{ id: "copy", label: t("menu.copy"), icon: "copy", shortcut: `${mod}+C`, onSelect: () => copy(text, false) }];
  }
  const readOnly = isField(editable) ? editable.readOnly || editable.disabled : false;
  // The browser never copies out of a password field, and neither does this menu.
  const secret = isField(editable) && editable.type === "password";
  const has = text !== "";
  const empty = isField(editable) ? editable.value === "" : (editable.textContent ?? "") === "";
  return [
    {
      id: "cut",
      label: t("menu.cut"),
      icon: "scissors",
      shortcut: `${mod}+X`,
      disabled: !has || readOnly || secret,
      onSelect: () => {
        if (!exec("cut")) {
          copy(text, false);
          exec("delete");
        }
      },
    },
    { id: "copy", label: t("menu.copy"), icon: "copy", shortcut: `${mod}+C`, disabled: !has || secret, onSelect: () => copy(text, true) },
    { id: "paste", label: t("menu.paste"), icon: "paste", shortcut: `${mod}+V`, disabled: readOnly, onSelect: () => void paste(editable) },
    { id: "sep", separator: true },
    {
      id: "all",
      label: t("menu.selectAll"),
      icon: "selectAll",
      shortcut: `${mod}+A`,
      disabled: empty,
      onSelect: () => (isField(editable) ? editable.select() : exec("selectAll")),
    },
  ];
}
