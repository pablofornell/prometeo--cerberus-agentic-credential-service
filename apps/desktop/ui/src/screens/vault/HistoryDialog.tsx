import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { ItemSummaryView_Serialize as Item } from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { Button, Dialog, errorText, ErrorState, RowList, Skeleton, useToast } from "../../ui";
import { formatDateTime } from "./kinds";
import { messages } from "./messages";
import { invalidateItems, useItemDetail, useVersions } from "./queries";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  item: Item;
  canRestore: boolean;
}

/** Version history of one item (`item_versions`) with restore (`item_restore_version`). Titles only: no secret values. */
export function HistoryDialog({ open, onOpenChange, item, canRestore }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const versions = useVersions(item.id, open);
  const detail = useItemDetail(item.id);
  const [busy, setBusy] = useState<number | null>(null);
  const current = detail.data?.version;

  const restore = async (version: number) => {
    setBusy(version);
    try {
      await ipc.itemRestoreVersion(item.id, version);
      invalidateItems(queryClient);
      toast.push({ tone: "success", title: tr("history.restored", { version }) });
      onOpenChange(false);
    } catch (error) {
      toast.push({ tone: "error", title: tr("history.fail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    } finally {
      setBusy(null);
    }
  };

  const rows = [...(versions.data ?? [])].sort((a, b) => b.version - a.version);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={tr("history.title", { title: item.title })}
      description={tr("history.body")}
      footer={<Button onClick={() => onOpenChange(false)}>{tr("history.close")}</Button>}
    >
      {versions.isPending && <Skeleton label={t("secret.loading")} rows={3} />}
      {versions.isError && <ErrorState action={tr("history.loadFail")} error={versions.error} onRetry={() => void versions.refetch()} retrying={versions.isFetching} />}
      {versions.data && rows.length <= 1 && <p className="small muted">{tr("history.empty")}</p>}
      {rows.length > 0 && (
        <RowList
          label={tr("history.title", { title: item.title })}
          rows={rows}
          rowKey={(v) => String(v.version)}
          renderRow={(v) => (
            <>
              <div className="grow">
                <div className="title">{tr("history.version", { version: v.version })}</div>
                <div className="sub">{formatDateTime(v.created_at)}</div>
              </div>
              {v.version === current ? (
                <span className="chip">{tr("history.current")}</span>
              ) : (
                canRestore && (
                  <Button size="sm" loading={busy === v.version} aria-label={tr("history.restoreLabel", { version: v.version })} onClick={() => void restore(v.version)}>
                    {tr("history.restore")}
                  </Button>
                )
              )}
            </>
          )}
        />
      )}
    </Dialog>
  );
}
