import { useState } from "react";
import { useScreenT } from "../../../i18n";
import { Button } from "../../../ui";
import { ExportDialog } from "./ExportDialog";
import { ImportWizard } from "./ImportWizard";
import { messages } from "./messages";

/** The "Import CSV" button with its wizard. The caller decides who sees it (operators and owners). */
export function ImportButton({
  size = "md",
  variant,
  disabled,
  defaultOpen = false,
}: {
  size?: "sm" | "md";
  variant?: "ghost";
  disabled?: boolean;
  /** Open the wizard on mount (deep link `?import=1` from the command palette). */
  defaultOpen?: boolean;
}) {
  const tr = useScreenT(messages);
  const [open, setOpen] = useState(defaultOpen && !disabled);
  return (
    <>
      <Button size={size} variant={variant} icon="upload" disabled={disabled} onClick={() => setOpen(true)}>
        {tr("import.button")}
      </Button>
      {open && <ImportWizard open={open} onOpenChange={setOpen} />}
    </>
  );
}

/**
 * The "Export CSV" button with its dialog. The caller decides who sees it (owners). It is red where it sits next to
 * other settings; in the vault top bar it is a quiet ghost button and the dialog carries the plain-text warning.
 */
export function ExportButton({ size = "md", variant = "danger-ghost", disabled }: { size?: "sm" | "md"; variant?: "danger-ghost" | "ghost"; disabled?: boolean }) {
  const tr = useScreenT(messages);
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size={size} variant={variant} icon="download" disabled={disabled} onClick={() => setOpen(true)}>
        {tr("export.button")}
      </Button>
      {open && <ExportDialog open={open} onOpenChange={setOpen} />}
    </>
  );
}
