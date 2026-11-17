import * as RadixDialog from "@radix-ui/react-dialog";
import { useRef, type ReactNode } from "react";
import { t } from "../i18n";
import { Button, HoldButton } from "./Button";
import { cx } from "./cx";
import { Icon } from "./Icon";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** What the dialog does, read after the title. */
  description?: string;
  children?: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  /** Close by Esc, outside click or the close button. Turn it off for one-time reveal dialogs. */
  dismissible?: boolean;
  /** Which part gets focus first. Danger dialogs set it to Cancel. */
  initialFocus?: React.RefObject<HTMLElement | null>;
}

/** Radix Dialog with the Cerberus look. Traps focus, closes on Esc, returns focus to the opener. */
export function Dialog({ open, onOpenChange, title, description, children, footer, wide, dismissible = true, initialFocus }: DialogProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="dlg-overlay" />
        <RadixDialog.Content
          className={cx("dlg", wide && "wide")}
          onOpenAutoFocus={(e) => {
            if (initialFocus?.current) {
              e.preventDefault();
              initialFocus.current.focus();
            }
          }}
          onEscapeKeyDown={(e) => !dismissible && e.preventDefault()}
          onPointerDownOutside={(e) => !dismissible && e.preventDefault()}
          onInteractOutside={(e) => !dismissible && e.preventDefault()}
          {...(description ? {} : { "aria-describedby": undefined })}
        >
          <div className="head">
            <RadixDialog.Title asChild>
              <h2>{title}</h2>
            </RadixDialog.Title>
            {description && <RadixDialog.Description className="secondary">{description}</RadixDialog.Description>}
          </div>
          {children && <div className="body">{children}</div>}
          {footer && <div className="foot">{footer}</div>}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** A question with the object: "Delete Shop staging admin?" */
  title: string;
  /** What happens, and whether it can be undone. */
  description: string;
  confirmLabel: string;
  onConfirm: () => void;
  tone?: "neutral" | "danger";
  /** Replace the confirm click by a hold (ms). */
  holdMs?: number;
  loading?: boolean;
}

/** Danger dialogs start focus on Cancel. Esc cancels, it never confirms. */
export function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel, onConfirm, tone = "neutral", holdMs, loading }: ConfirmDialogProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const danger = tone === "danger";
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      initialFocus={danger ? cancelRef : undefined}
      footer={
        <>
          <Button ref={cancelRef} onClick={() => onOpenChange(false)}>
            {t("dialog.cancel")}
          </Button>
          {holdMs ? (
            <HoldButton holdMs={holdMs} variant={danger ? "danger" : "primary"} onHold={onConfirm} disabled={loading}>
              {confirmLabel}
            </HoldButton>
          ) : (
            <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={loading}>
              {confirmLabel}
            </Button>
          )}
        </>
      }
    />
  );
}

interface DrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}

/** A panel from the right edge (420 px). Same focus rules as the dialog. */
export function Drawer({ open, onOpenChange, title, description, children, footer }: DrawerProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="dlg-overlay" />
        <RadixDialog.Content className="drawer-panel" {...(description ? {} : { "aria-describedby": undefined })}>
          <div className="drawer-head">
            <RadixDialog.Title asChild>
              <h2>{title}</h2>
            </RadixDialog.Title>
            <RadixDialog.Close className="btn sm ghost icon-only" aria-label={t("dialog.close")}>
              <Icon name="x" />
            </RadixDialog.Close>
          </div>
          {description && <RadixDialog.Description className="secondary drawer-desc">{description}</RadixDialog.Description>}
          <div className="drawer-body">{children}</div>
          {footer && <div className="foot">{footer}</div>}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}
