import { useEffect, useMemo, useState } from "react";
import { useScreenT } from "../../i18n";
import { isLockError } from "../../ipc/client";
import { useOperators } from "../../ipc/queries";
import { useHashQuery } from "../../shell/location";
import { PageActions } from "../../shell/PageActions";
import { LockedState } from "../../shell/LockedState";
import { useCan } from "../../state/session";
import { Button, EmptyState, ErrorState, Icon, Input, Select, SegmentedControl, Skeleton } from "../../ui";
import "./vault.css";
import { Facets } from "./Facets";
import { applyFilters, categoryFacets, hasActiveFilters, NO_FILTERS, roleOptions, tagFacets, workspaceCounts, type Filters } from "./filters";
import { ItemDrawer } from "./ItemDrawer";
import { ItemList } from "./ItemList";
import { ENVIRONMENTS, KIND_ORDER, kindLabel, ROLE_PRESETS } from "./kinds";
import { messages } from "./messages";
import { clearSelection, peekSelection } from "./selection";
import { useAgentNames, useAllItems, useExposureRefresh, useSearchIds, useWorkspaces } from "./queries";
import { EMPTY_STATE_SLOTS, renderSlots, TOP_BAR_SLOTS } from "./slots";
import { WorkspaceDialog } from "./WorkspaceDialog";

type View = "list" | "grid";
const VIEW_KEY = "cerberus.vault.view";

function loadView(): View {
  try {
    return window.localStorage.getItem(VIEW_KEY) === "grid" ? "grid" : "list";
  } catch {
    return "list";
  }
}

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return debounced;
}

/** Screen 4: facets, list or grid, filters, details. */
export default function VaultScreen() {
  const tr = useScreenT(messages);
  const hashQuery = useHashQuery();
  const canWrite = useCan("operator");
  const canReveal = useCan("operator");
  const items = useAllItems();
  const workspaces = useWorkspaces();
  const agents = useAgentNames();
  const operators = useOperators();
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [view, setViewState] = useState<View>(loadView);
  const [selectedId, setSelectedId] = useState<string | null>(() => hashQuery.get("item") ?? peekSelection());
  const [wsOpen, setWsOpen] = useState(false);
  const query = useDebounced(filters.q.trim(), 200);
  const found = useSearchIds(query);
  useExposureRefresh();
  useEffect(() => clearSelection, []);

  const setView = (next: View) => {
    setViewState(next);
    try {
      window.localStorage.setItem(VIEW_KEY, next);
    } catch {
      // The view is a convenience. Without storage it resets on the next start.
    }
  };
  const patch = (next: Partial<Filters>) => setFilters((prev) => ({ ...prev, ...next }));

  const all = useMemo(() => items.data ?? [], [items.data]);
  const matchIds = useMemo(() => (query === "" ? null : new Set((found.data ?? []).map((i) => i.id))), [query, found.data]);
  const visible = useMemo(() => applyFilters(all, filters, matchIds), [all, filters, matchIds]);
  const selected = all.find((i) => i.id === selectedId) ?? null;

  const agentNames = useMemo(() => new Map((agents.data ?? []).map((a) => [a.id, a.name])), [agents.data]);
  const operatorNames = useMemo(() => new Map((operators.data ?? []).map((o) => [o.id, o.label])), [operators.data]);
  const wsList = workspaces.data ?? [];

  const slotContext = { canWrite, hasItems: all.length > 0, hasWorkspace: wsList.length > 0, openImport: hashQuery.get("import") === "1" };

  if (items.isPending) {
    return (
      <div className="vb-browser" aria-busy="true">
        <div className="vb-facets" aria-hidden="true">
          <Skeleton label={tr("loading.items")} rows={5} />
        </div>
        <div className="vb-listcol">
          <Skeleton label={tr("loading.items")} rows={6} />
        </div>
        <div className="drawer vb-drawer vb-loading-drawer" aria-hidden="true">
          <Skeleton label={tr("loading.items")} variant="block" />
        </div>
      </div>
    );
  }
  if (items.isError) {
    if (isLockError(items.error)) return <LockedState reason={tr("locked")} />;
    return <ErrorState as="h2" action={tr("error.action")} error={items.error} onRetry={() => void items.refetch()} retrying={items.isFetching} />;
  }

  if (all.length === 0 && !hasActiveFilters(filters)) {
    const noWorkspace = !workspaces.isPending && wsList.length === 0;
    return (
      <>
        <PageActions>{renderSlots(TOP_BAR_SLOTS, slotContext)}</PageActions>
        <EmptyState
          as="h2"
          gate
          title={noWorkspace ? tr("empty.noWorkspace.title") : tr("empty.title")}
          body={noWorkspace ? tr("empty.noWorkspace.body") : tr("empty.body")}
          action={
            <>
              {canWrite && noWorkspace && (
                <Button variant="primary" icon="plus" onClick={() => setWsOpen(true)}>
                  {tr("empty.newWorkspace")}
                </Button>
              )}
              {renderSlots(EMPTY_STATE_SLOTS, slotContext)}
            </>
          }
        />
        <WorkspaceDialog open={wsOpen} onOpenChange={setWsOpen} />
      </>
    );
  }

  const total = visible.length;
  const countLine = filters.workspace
    ? tr(total === 1 ? "list.count.ws.one" : "list.count.ws", { count: total, workspace: filters.workspace })
    : tr(total === 1 ? "list.count.one" : "list.count.all", { count: total });

  return (
    <div className="vb-browser">
      <PageActions>{renderSlots(TOP_BAR_SLOTS, slotContext)}</PageActions>
      <Facets
        workspaces={wsList}
        totalItems={all.length}
        workspaceCount={workspaceCounts(all)}
        categories={categoryFacets(all)}
        tags={tagFacets(all)}
        filters={filters}
        onChange={patch}
        canAddWorkspace={canWrite}
        onAddWorkspace={() => setWsOpen(true)}
      />

      <section className="vb-listcol" aria-label={tr("list.label")}>
        <div className="vb-toolbar" role="search">
          <label className="vb-search">
            <span className="sr-only">{tr("toolbar.searchLabel")}</span>
            <Icon name="search" />
            <Input
              data-search
              type="search"
              placeholder={`${tr("toolbar.search")}  ( / )`}
              value={filters.q}
              autoComplete="off"
              onChange={(e) => patch({ q: e.target.value })}
              onKeyDown={(e) => {
                if (e.key === "Escape" && filters.q !== "") {
                  e.stopPropagation();
                  patch({ q: "" });
                }
              }}
            />
          </label>
          <Select
            aria-label={tr("toolbar.kind")}
            value={filters.kind}
            onChange={(e) => patch({ kind: e.target.value as Filters["kind"] })}
            options={[{ value: "", label: tr("toolbar.allKinds") }, ...KIND_ORDER.map((k) => ({ value: k, label: kindLabel(k) }))]}
          />
          <Select
            aria-label={tr("toolbar.env")}
            value={filters.env}
            onChange={(e) => patch({ env: e.target.value as Filters["env"] })}
            options={[{ value: "", label: tr("toolbar.allEnvs") }, ...ENVIRONMENTS.map((e) => ({ value: e, label: e }))]}
          />
          <Select
            aria-label={tr("toolbar.role")}
            value={filters.role}
            onChange={(e) => patch({ role: e.target.value })}
            options={[{ value: "", label: tr("toolbar.allRoles") }, ...roleOptions(all, ROLE_PRESETS).map((r) => ({ value: r, label: r }))]}
          />
          <SegmentedControl
            label={tr("toolbar.view")}
            value={view}
            onChange={setView}
            options={[
              { value: "list", label: tr("toolbar.list") },
              { value: "grid", label: tr("toolbar.grid") },
            ]}
          />
        </div>
        <div className="vb-count" role="status">
          {countLine}
        </div>
        {total === 0 ? (
          <EmptyState
            as="h2"
            icon="search"
            title={tr("list.noMatch.title")}
            body={tr("list.noMatch.body")}
            action={
              <Button onClick={() => setFilters(NO_FILTERS)}>{tr("toolbar.clear")}</Button>
            }
          />
        ) : (
          <ItemList
            items={visible}
            view={view}
            selectedId={selected?.id ?? null}
            onSelect={setSelectedId}
            onOpen={() => document.getElementById("vb-d-title")?.focus()}
            agentNames={agentNames}
          />
        )}
      </section>

      <ItemDrawer item={selected} canEdit={canWrite} canReveal={canReveal} agentNames={agentNames} operatorNames={operatorNames} onClose={() => setSelectedId(null)} />
      <WorkspaceDialog open={wsOpen} onOpenChange={setWsOpen} onCreated={(ws) => patch({ workspace: ws.slug })} />
    </div>
  );
}
