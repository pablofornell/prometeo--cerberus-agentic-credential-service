import type { WorkspaceView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { Icon, IconButton } from "../../ui";
import type { Facet, Filters } from "./filters";
import { categoryIcon } from "./kinds";
import { messages } from "./messages";

interface Props {
  workspaces: readonly WorkspaceView[];
  totalItems: number;
  workspaceCount: ReadonlyMap<string, number>;
  categories: readonly Facet[];
  tags: readonly Facet[];
  filters: Filters;
  onChange: (patch: Partial<Filters>) => void;
  /** Only operators and owners can add a workspace. */
  canAddWorkspace: boolean;
  onAddWorkspace: () => void;
}

/** The left column: workspaces and categories are single choice, tags too. A pressed button is the choice. */
export function Facets({ workspaces, totalItems, workspaceCount, categories, tags, filters, onChange, canAddWorkspace, onAddWorkspace }: Props) {
  const tr = useScreenT(messages);
  return (
    <nav className="vb-facets" aria-label={tr("filters.aria")}>
      <div>
        <div className="vb-facet-head">
          <h2 id="vb-ws-h">{tr("filters.workspaces")}</h2>
          {canAddWorkspace && <IconButton icon="plus" size="sm" label={tr("filters.newWorkspace")} onClick={onAddWorkspace} />}
        </div>
        <ul aria-labelledby="vb-ws-h">
          <li>
            <button type="button" aria-pressed={filters.workspace === null} onClick={() => onChange({ workspace: null })}>
              <Icon name="layers" />
              {tr("filters.allWorkspaces")}
              <span className="n">{totalItems}</span>
            </button>
          </li>
          {workspaces.map((ws) => (
            <li key={ws.id}>
              <button type="button" aria-pressed={filters.workspace === ws.slug} onClick={() => onChange({ workspace: filters.workspace === ws.slug ? null : ws.slug })}>
                <Icon name="layers" />
                {ws.slug}
                <span className="n">{workspaceCount.get(ws.slug) ?? 0}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <div className="vb-facet-head">
          <h2 id="vb-cat-h">{tr("filters.categories")}</h2>
        </div>
        <ul aria-labelledby="vb-cat-h">
          {categories.map((c) => (
            <li key={c.name}>
              <button type="button" aria-pressed={filters.category === c.name} onClick={() => onChange({ category: filters.category === c.name ? null : c.name })}>
                <Icon name={categoryIcon(c.name)} />
                {c.name}
                <span className="n">{c.count}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <div className="vb-facet-head">
          <h2 id="vb-tag-h">{tr("filters.tags")}</h2>
        </div>
        {tags.length === 0 ? (
          <p className="small muted vb-facet-empty">{tr("filters.noTags")}</p>
        ) : (
          <div className="vb-tags" role="group" aria-labelledby="vb-tag-h">
            {tags.map((tag) => (
              <button key={tag.name} className="chip" type="button" aria-pressed={filters.tag === tag.name} onClick={() => onChange({ tag: filters.tag === tag.name ? null : tag.name })}>
                #{tag.name}
              </button>
            ))}
          </div>
        )}
      </div>
    </nav>
  );
}
