// Action slots of the vault screen. Each entry shows itself only when `visible` says so. T23 added the CSV import and export.
import { Fragment, type ReactNode } from "react";
import { useLocation } from "wouter";
import { useScreenT } from "../../i18n";
import { useCan } from "../../state/session";
import { Button, Kbd } from "../../ui";
import { ExportButton, ImportButton } from "./csv";
import { messages } from "./messages";

export interface SlotContext {
  /** Operators and owners can add and change items. Viewers cannot. */
  canWrite: boolean;
  /** The vault has at least one item. */
  hasItems: boolean;
  /** The vault has at least one workspace. */
  hasWorkspace: boolean;
  /** The page was opened with `?import=1`: the top bar import button opens its wizard. */
  openImport: boolean;
}

export interface VaultSlot {
  id: string;
  visible: (ctx: SlotContext) => boolean;
  render: (ctx: SlotContext) => ReactNode;
}

function NewItemButton({ hint }: { hint: boolean }) {
  const tr = useScreenT(messages);
  const [, navigate] = useLocation();
  return (
    <Button variant="primary" icon="plus" onClick={() => navigate("~/editor/new")}>
      {tr("newItem")}
      {hint && <Kbd>N</Kbd>}
    </Button>
  );
}

/** Owner only: the export holds every secret in plain text. The backend checks the role again. */
function OwnerExportButton() {
  return useCan("owner") ? <ExportButton variant="ghost" /> : null;
}

/** Buttons in the top bar, left to right. The primary action comes last. */
export const TOP_BAR_SLOTS: readonly VaultSlot[] = [
  { id: "csv-export", visible: (ctx) => ctx.hasItems, render: () => <OwnerExportButton /> },
  { id: "csv-import", visible: (ctx) => ctx.canWrite && ctx.hasWorkspace, render: (ctx) => <ImportButton variant="ghost" defaultOpen={ctx.openImport} /> },
  { id: "new-item", visible: (ctx) => ctx.canWrite && ctx.hasWorkspace, render: () => <NewItemButton hint /> },
];

/** Buttons in the empty state, left to right. */
export const EMPTY_STATE_SLOTS: readonly VaultSlot[] = [
  { id: "csv-import", visible: (ctx) => ctx.canWrite && ctx.hasWorkspace, render: () => <ImportButton /> },
  { id: "new-item", visible: (ctx) => ctx.canWrite && ctx.hasWorkspace, render: () => <NewItemButton hint={false} /> },
];

export function renderSlots(slots: readonly VaultSlot[], ctx: SlotContext): ReactNode[] {
  return slots.filter((slot) => slot.visible(ctx)).map((slot) => <Fragment key={slot.id}>{slot.render(ctx)}</Fragment>);
}
