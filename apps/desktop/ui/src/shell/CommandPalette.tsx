import * as RadixDialog from "@radix-ui/react-dialog";
import { useId, useMemo, useState } from "react";
import { useLocation } from "wouter";
import { t } from "../i18n";
import { ipc } from "../ipc/client";
import { qk } from "../ipc/keys";
import { useIpcQuery } from "../ipc/queries";
import { Icon, Kbd, cx } from "../ui";
import { buildCommands, filterCommands, GROUP_ORDER, type Command, type CommandGroup } from "./commands";
import { useShellActions } from "./actions";
import { closeOverlay, overlayStore } from "./uiStore";

type Row = Command;

const GROUP_LABEL: Record<CommandGroup, Parameters<typeof t>[0]> = {
  goto: "palette.group.goto",
  create: "palette.group.create",
  vault: "palette.group.vault",
  view: "palette.group.view",
  items: "palette.group.items",
  agents: "palette.group.agents",
};

/** Ctrl/Cmd+K. A dialog with a combobox and a listbox. Item and agent results show metadata only. */
export function CommandPalette() {
  const open = overlayStore.use() === "palette";
  return (
    <RadixDialog.Root open={open} onOpenChange={(next) => !next && closeOverlay()}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="dlg-overlay" />
        {open && <PaletteBody />}
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

function PaletteBody() {
  const actions = useShellActions();
  const [, navigate] = useLocation();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const term = query.trim();

  const items = useIpcQuery(qk.items.search(term), () => ipc.itemList({ q: term }), { enabled: term.length >= 2 });
  const agents = useIpcQuery(qk.agents(), () => ipc.agentList());

  const rows = useMemo<Row[]>(() => {
    const close = (to: string) => () => {
      closeOverlay();
      navigate(to);
    };
    const wrapped = buildCommands({
      ...actions,
      navigate: (to) => {
        closeOverlay();
        actions.navigate(to);
      },
      lock: () => {
        closeOverlay();
        actions.lock();
      },
      exportCa: () => {
        closeOverlay();
        actions.exportCa();
      },
      createBackup: () => {
        closeOverlay();
        actions.createBackup();
      },
      showShortcuts: actions.showShortcuts,
      panic: actions.panic,
    });
    const found = filterCommands(wrapped, term);
    const itemRows: Row[] = (items.data ?? []).slice(0, 6).map((item) => ({
      id: `item-${item.id}`,
      group: "items",
      label: item.title,
      icon: "key",
      keywords: `${item.workspace} ${item.environment}`,
      run: close(`/vault?item=${encodeURIComponent(item.id)}`),
    }));
    const agentRows: Row[] = term
      ? filterCommands(
          (agents.data ?? []).map((a) => ({ id: a.id, label: a.name })),
          term,
        )
          .slice(0, 4)
          .map((a) => ({ id: `agent-${a.id}`, group: "agents" as const, label: a.label, icon: "bot" as const, run: close(`/agents?agent=${encodeURIComponent(a.id)}`) }))
      : [];
    return [...found, ...itemRows, ...agentRows].sort((a, b) => GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group));
  }, [actions, term, items.data, agents.data, navigate]);

  const current = Math.min(active, Math.max(rows.length - 1, 0));
  const run = (row: Row | undefined) => row?.run();

  return (
    <RadixDialog.Content className="dlg palette" aria-describedby={undefined}>
      <RadixDialog.Title className="sr-only">{t("palette.title")}</RadixDialog.Title>
      <div className="search">
        <Icon name="search" size={18} />
        <input
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={rows[current] ? `${listId}-${current}` : undefined}
          aria-label={t("palette.placeholder")}
          placeholder={t("palette.placeholder")}
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((i) => (rows.length ? (Math.min(i, rows.length - 1) + 1) % rows.length : 0));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((i) => (rows.length ? (Math.min(i, rows.length - 1) - 1 + rows.length) % rows.length : 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              run(rows[current]);
            }
          }}
        />
      </div>
      <ul role="listbox" id={listId} aria-label={t("palette.title")}>
        {rows.length === 0 && <li className="group" role="presentation">{t("palette.empty")}</li>}
        {rows.map((row, i) => (
          <PaletteRow
            key={row.id}
            row={row}
            id={`${listId}-${i}`}
            selected={i === current}
            header={rows[i - 1]?.group !== row.group}
            onHover={() => setActive(i)}
          />
        ))}
      </ul>
      <div className="foot">
        <span>
          <Kbd>↑</Kbd> <Kbd>↓</Kbd> {t("palette.footer.move")}
        </span>
        <span>
          <Kbd>Enter</Kbd> {t("palette.footer.open")}
        </span>
        <span>
          <Kbd>Esc</Kbd> {t("palette.footer.close")}
        </span>
      </div>
    </RadixDialog.Content>
  );
}

function PaletteRow({ row, id, selected, header, onHover }: { row: Row; id: string; selected: boolean; header: boolean; onHover: () => void }) {
  return (
    <>
      {header && (
        <li className="group" role="presentation">
          {t(GROUP_LABEL[row.group])}
        </li>
      )}
      <li id={id} role="option" aria-selected={selected} className={cx(row.danger && "danger")} onMouseMove={onHover} onClick={row.run}>
        <Icon name={row.icon} />
        <span>{row.label}</span>
        {row.keys && (
          <span className="hint">
            {row.keys.map((k) => (
              <Kbd key={k}>{k}</Kbd>
            ))}
          </span>
        )}
      </li>
    </>
  );
}
