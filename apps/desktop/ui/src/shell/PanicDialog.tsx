import { useMutation, useQueryClient } from "@tanstack/react-query";
import { t } from "../i18n";
import { ipc } from "../ipc/client";
import { qk } from "../ipc/keys";
import { Button, Dialog, HoldButton, useToast } from "../ui";
import { closeOverlay, overlayStore } from "./uiStore";

/** "Lock and revoke all": a 1 s hold is the safety. There is no single key for it (IA section 5). */
export function PanicDialog() {
  const overlay = overlayStore.use();
  const toast = useToast();
  const queryClient = useQueryClient();
  const panic = useMutation({
    mutationFn: () => ipc.vaultPanic(),
    onSuccess: () => {
      closeOverlay();
      toast.push({ tone: "success", title: t("panic.done") });
      void queryClient.invalidateQueries({ queryKey: qk.vault.status() });
    },
  });
  return (
    <Dialog
      open={overlay === "panic"}
      onOpenChange={(open) => !open && closeOverlay()}
      title={t("panic.title")}
      description={t("panic.body")}
      footer={
        <>
          <Button onClick={closeOverlay}>{t("panic.cancel")}</Button>
          <HoldButton holdMs={1000} variant="danger" icon="siren" disabled={panic.isPending} onHold={() => panic.mutate()}>
            {t("panic.hold")}
          </HoldButton>
        </>
      }
    />
  );
}
