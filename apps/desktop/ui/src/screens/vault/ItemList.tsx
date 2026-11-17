import type { KeyboardEvent } from "react";
import type { ItemSummaryView_Serialize as Item } from "../../bindings";
import { useScreenT } from "../../i18n";
import { AgentMadeBadge, cx, EnvBadge, KindIcon, RoleChip, TtlRing } from "../../ui";
import { ttlSpan } from "./filters";
import { isSessionKind, kindLabel } from "./kinds";
import { messages } from "./messages";

interface Props {
  items: readonly Item[];
  view: "list" | "grid";
  selectedId: string | null;
  onSelect: (id: string) => void;
  /** Enter on an option: move focus to the details. */
  onOpen: () => void;
  /** Names of agents by ID, for the "created by an agent" badge. */
  agentNames: ReadonlyMap<string, string>;
}

const optionId = (id: string) => `vb-opt-${id}`;

function creatorAgent(item: Item, names: ReadonlyMap<string, string>): string | null {
  if (!item.created_by.startsWith("agent:")) return null;
  const id = item.created_by.slice("agent:".length);
  return names.get(id) ?? id;
}

function Ttl({ item, size }: { item: Item; size: 20 | 22 }) {
  const span = isSessionKind(item.kind) ? ttlSpan(item) : null;
  return span ? <TtlRing total={span.total} endsAt={span.endsAt} size={size} /> : null;
}

/**
 * One listbox for both views. Arrow keys move the selection (and the open details), Home and End jump,
 * Enter moves focus to the details. Only one option is in the tab order.
 */
export function ItemList({ items, view, selectedId, onSelect, onOpen, agentNames }: Props) {
  const tr = useScreenT(messages);
  const tabbable = items.some((i) => i.id === selectedId) ? selectedId : items[0]?.id;

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    const index = items.findIndex((i) => optionId(i.id) === (event.target as HTMLElement).id);
    if (index < 0) return;
    let next: number;
    if (event.key === "ArrowDown" || event.key === "ArrowRight") next = Math.min(items.length - 1, index + 1);
    else if (event.key === "ArrowUp" || event.key === "ArrowLeft") next = Math.max(0, index - 1);
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = items.length - 1;
    else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(items[index]?.id ?? "");
      onOpen();
      return;
    } else return;
    event.preventDefault();
    const target = items[next];
    if (!target) return;
    onSelect(target.id);
    document.getElementById(optionId(target.id))?.focus();
  };

  const optionProps = (item: Item) => ({
    id: optionId(item.id),
    role: "option" as const,
    tabIndex: item.id === tabbable ? 0 : -1,
    "aria-selected": item.id === selectedId,
    onClick: () => onSelect(item.id),
  });

  if (view === "grid") {
    return (
      <ul className="vb-tiles" role="listbox" aria-label={tr("list.label")} onKeyDown={onKeyDown}>
        {items.map((item) => {
          const agent = creatorAgent(item, agentNames);
          return (
            <li key={item.id} {...optionProps(item)} className={cx(item.environment === "prod" && "prod")}>
              <div className="top">
                <KindIcon kind={item.kind} prod={item.environment === "prod"} />
                <span className="vb-meta">
                  <Ttl item={item} size={22} />
                  <EnvBadge env={item.environment} />
                </span>
              </div>
              <div>
                <div className="title">{item.title}</div>
                <div className="sub">{tr("list.sub", { kind: kindLabel(item.kind), workspace: item.workspace })}</div>
              </div>
              <div className="row-inline">
                {item.role_label && <RoleChip role={item.role_label} />}
                {agent && <AgentMadeBadge agent={agent} />}
              </div>
            </li>
          );
        })}
      </ul>
    );
  }

  return (
    <ul className="rows vb-items" role="listbox" aria-label={tr("list.label")} onKeyDown={onKeyDown}>
      {items.map((item) => {
        const agent = creatorAgent(item, agentNames);
        return (
          <li key={item.id} {...optionProps(item)} className={cx("interactive", item.environment === "prod" && "prod")}>
            <KindIcon kind={item.kind} prod={item.environment === "prod"} />
            <div className="grow">
              <div className="title">{item.title}</div>
              <div className="sub">
                {tr("list.sub", { kind: kindLabel(item.kind), workspace: item.workspace })}
                {item.target ? <span className="mono">{`, ${item.target}`}</span> : null}
              </div>
            </div>
            <span className="vb-meta">
              {agent && <AgentMadeBadge agent={agent} />}
              <Ttl item={item} size={22} />
              {item.role_label && (
                <span className="vb-role">
                  <RoleChip role={item.role_label} />
                </span>
              )}
              <EnvBadge env={item.environment} />
            </span>
          </li>
        );
      })}
    </ul>
  );
}
