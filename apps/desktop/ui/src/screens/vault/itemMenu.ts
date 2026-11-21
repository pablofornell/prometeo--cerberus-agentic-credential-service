import { useLocation } from "wouter";
import type { ItemSummaryView_Serialize as Item } from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { ipc } from "../../ipc/client";
import { useRemoteUnsupported } from "../../state/backendMode";
import { useSecretCopy, type MenuEntry } from "../../ui";
import { messages } from "./messages";
import { SECRET_FIELDS } from "./secrets";

interface Options {
  /** Operators and owners edit and delete. Viewers see no action. */
  canEdit: boolean;
  /** Viewers cannot copy values. */
  canReveal: boolean;
  /** Select the item and move the focus to its details. */
  onOpen: (item: Item) => void;
  /** Ask to delete. The caller opens `DeleteItemDialog`, so the confirm step is the same as in the drawer. */
  onDelete: (item: Item) => void;
}

/**
 * The context menu of a vault item. It calls what the drawer calls: `clipboard_copy_secret` (with the same toast and the
 * 30 s clipboard clear), the editor route, and the delete confirm dialog. Revealing a value stays hold to reveal in the
 * details: the menu opens them, it never shows a secret itself.
 */
export function useItemMenu({ canEdit, canReveal, onOpen, onDelete }: Options): (item: Item) => MenuEntry[] {
  const tr = useScreenT(messages);
  const [, navigate] = useLocation();
  const copySecret = useSecretCopy();
  // Remote mode: copy needs the clipboard timer of this device (DEC-RM-14).
  const noCopy = useRemoteUnsupported("clipboard_copy_secret");

  return (item) => {
    const entries: MenuEntry[] = [{ id: "open", label: tr("menu.open"), icon: "eye", onSelect: () => onOpen(item) }];
    if (canReveal && !noCopy) {
      for (const def of SECRET_FIELDS[item.kind]) {
        const field = def.field;
        if (field === null) continue;
        entries.push({ id: `copy-${field}`, label: t("secret.copy", { label: tr(def.label) }), icon: "copy", onSelect: () => void copySecret(() => ipc.clipboardCopySecret(item.id, field)) });
      }
      if (item.has_totp) {
        entries.push({ id: "copy-totp", label: t("secret.copy", { label: tr("drawer.otp") }), icon: "copy", onSelect: () => void copySecret(() => ipc.clipboardCopySecret(item.id, "totp")) });
      }
    }
    if (canEdit) {
      entries.push(
        { id: "sep", separator: true },
        { id: "edit", label: tr("drawer.edit"), icon: "edit", onSelect: () => navigate(`~/editor/${encodeURIComponent(item.id)}`) },
        { id: "delete", label: tr("drawer.delete"), icon: "trash", danger: true, onSelect: () => onDelete(item) },
      );
    }
    return entries;
  };
}
