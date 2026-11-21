import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { ItemSummaryView_Serialize as Item } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { ConfirmDialog, errorText, useToast } from "../../ui";
import { messages } from "./messages";
import { invalidateItems, useItemDetail } from "./queries";

interface Props {
  item: Item;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** After the vault confirmed the delete. */
  onDeleted: () => void;
}

/** The confirm dialog and the delete of one item. The details drawer and the item context menu both open it. */
export function DeleteItemDialog({ item, open, onOpenChange, onDeleted }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const detail = useItemDetail(item.id);
  const [deleting, setDeleting] = useState(false);

  const remove = async () => {
    setDeleting(true);
    try {
      await ipc.itemDelete(item.id);
      toast.push({ tone: "success", title: tr("delete.done", { title: item.title }) });
      onOpenChange(false);
      invalidateItems(queryClient);
      onDeleted();
    } catch (error) {
      toast.push({ tone: "error", title: tr("delete.fail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    } finally {
      setDeleting(false);
    }
  };

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      tone="danger"
      title={tr("delete.title", { title: item.title })}
      description={tr("delete.body", { versions: detail.data?.version ?? 1, workspace: item.workspace, env: item.environment })}
      confirmLabel={tr("delete.confirm")}
      onConfirm={() => void remove()}
      loading={deleting}
    />
  );
}
